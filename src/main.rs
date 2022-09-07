use cached::proc_macro::io_cached;
use fast_socks5::client::Socks5Stream;
use futures_util::StreamExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::{http::HeaderValue, Body, Request, Response, StatusCode, Uri};
use hyper_tungstenite::HyperWebsocket;
use lazy_static::lazy_static;
use postgrest::Postgrest;
use prometheus::{
    HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
};
use reverse_proxy::AsyncRedisCache;
use serde::Deserialize;
use simple_hyper_server_tls::{hyper_from_pem_files, Protocols};
use std::io;
use std::time::Instant;
use std::vec::Vec;
use thiserror::Error;
use tokio::{try_join};
use url::Url;

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

lazy_static! {
    static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!(
                "socks5h://{}",
                dotenv::var("TOR_PROXY").expect("Missing TOR_PROXY env var")
            ))
            .expect("tor proxy should be there")
        )
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to generated request client!");
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref INCOMING_REQUESTS: IntCounter =
        IntCounter::new("incoming_requests", "Incoming Requests").expect("metric can be created");
    pub static ref CONNECTED_CLIENTS: IntGauge =
        IntGauge::new("connected_clients", "Connected Clients").expect("metric can be created");
    pub static ref RESPONSE_CODE_COLLECTOR: IntCounterVec = IntCounterVec::new(
        Opts::new("response_code", "Response Codes"),
        &["env", "statuscode", "type"]
    )
    .expect("metric can be created");
    pub static ref RESPONSE_TIME_COLLECTOR: HistogramVec = HistogramVec::new(
        HistogramOpts::new("response_time", "Response Times"),
        &["env"]
    )
    .expect("metric can be created");
}

fn register_custom_metrics() {
    REGISTRY
        .register(Box::new(INCOMING_REQUESTS.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(CONNECTED_CLIENTS.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(RESPONSE_CODE_COLLECTOR.clone()))
        .expect("collector can be registered");

    REGISTRY
        .register(Box::new(RESPONSE_TIME_COLLECTOR.clone()))
        .expect("collector can be registered");
}

#[derive(Deserialize, Debug, Clone)]
struct SupabaseTargetInfo {
    //host: String,
    target_url: String,
}

#[derive(Error, Debug, PartialEq, Clone)]
enum LoadingTargetError {
    #[error("error with redis cache `{0}`")]
    RedisError(String),
    #[error("error with supabase `{0}`")]
    SupabaseError(String),
}

#[io_cached(
    map_error = r##"|e| LoadingTargetError::RedisError(format!("{:?}", e))"##,
    type = "AsyncRedisCache<String, String>",
    create = r##" {
        AsyncRedisCache::new("dtv_proxy_cache", 1)
            .set_refresh(true)
            .build()
            .await
            .expect("error building redis cache")
    } "##
)]
async fn get_target_sub(host: String) -> Result<String, LoadingTargetError> {
    let url = dotenv::var("SUPABASE_SERVER").expect("No Supabase server provided");
    let admin_key = dotenv::var("SUPABASE_ADMIN_KEY").expect("No Supabase  admin key provided");
    let client = Postgrest::new(format!("{}/rest/v1", url))
        .insert_header("apikey", &admin_key)
        .insert_header("authorization", format!("Bearer {}", admin_key));
    let resp = client
        .from("reverse_proxies")
        .eq("host", host)
        .select("target_url")
        .execute()
        .await;
    if resp.is_err() {
        Err(LoadingTargetError::SupabaseError(
            resp.unwrap_err().to_string(),
        ))
    } else {
        let data = resp.unwrap().json::<Vec<SupabaseTargetInfo>>().await;
        if let Err(supabase_error) = data {
            Err(LoadingTargetError::SupabaseError(
                supabase_error.to_string()
            ))
        } else {
            let data = data.unwrap();
            if data.is_empty() {
                Err(LoadingTargetError::SupabaseError("Not found".to_string()))
            } else {
                Ok(data[0].target_url.clone())
            }
        }
    }
}

async fn get_target(host: String) -> Result<Url, LoadingTargetError> {
    let target = get_target_sub(host).await;
    if target.is_err() {
        Err(target.unwrap_err())
    } else {
        let target = target.unwrap();
        let url = Url::parse(&target).unwrap();
        Ok(url)
    }
}

/// Handle a HTTP or WebSocket request.
async fn handle_request(mut request: Request<Body>) -> Result<Response<Body>, Error> {
    let now = Instant::now();
    log::debug!("Received request!");
    let host = request.uri().host();
    let real_host: &str;
    if host.is_none() {
        let host = request.headers().get("host");
        if host.is_none() {
            let mut res = Response::new(Body::from("Missing host header"));
            *res.status_mut() = StatusCode::BAD_REQUEST;
            track_status_code(res.status().as_u16().into(), "production");
            track_request_time(now.elapsed().as_secs_f64(), "production");
            return Ok(res);
        }
        real_host = host.unwrap().to_str().expect("Failed to parse host");
    } else {
        real_host = host.unwrap();
    }
    log::debug!("Got request to {}", real_host);
    let target = get_target(real_host.to_string()).await;
    if target.is_err() {
        log::error!("{:#?}", target.err().unwrap());
        let mut res = Response::new(Body::from(include_str!("static/minified/404.html")));
        *res.status_mut() = StatusCode::MISDIRECTED_REQUEST;
        track_status_code(res.status().as_u16().into(), "production");
        track_request_time(now.elapsed().as_secs_f64(), "production");
        return Ok(res);
    }
    let mut target = target.unwrap();
    // Check if the request is a websocket upgrade request.
    if hyper_tungstenite::is_upgrade_request(&request) {
        let (response, websocket) = hyper_tungstenite::upgrade(&mut request, None)?;

        // Spawn a task to handle the websocket connection.
        tokio::spawn(async move {
            if let Err(e) = serve_websocket(websocket, target, request.uri()).await {
                eprintln!("Error in websocket connection: {}", e);
            }
        });

        // Return the response so the spawned future can continue.
        Ok(response)
    } else {
        log::debug!("Sending proxy request");
        let request_url = request.uri();
        let mut headers = request.headers().clone();
        headers.remove("X-Forwarded-For");
        headers.remove("X-Real-IP");
        headers.remove("X-Forwarded-Proto");
        headers.remove("X-Forwarded-Proto");
        headers.append(
            "X-Forwarded-For",
            HeaderValue::from_str(real_host).expect("Failed to turn host into a header"),
        );
        headers.append(
            "X-Real-IP",
            HeaderValue::from_str(real_host).expect("Failed to turn host into a header"),
        );
        headers.append(
            "Host",
            HeaderValue::from_str(real_host).expect("Failed to turn host into a header"),
        );
        headers.append(
            "X-Forwarded-Proto",
            HeaderValue::from_str(request_url.scheme_str().unwrap_or("https"))
                .expect("Invalid URL"),
        );
        log::debug!("{:#?}", headers);
        target.set_path(request_url.path());
        target.set_query(request_url.query());
        let res = REQWEST_CLIENT
            .request(request.method().clone(), target.clone())
            .headers(headers)
            .body(reqwest::Body::from(request.into_body()))
            .send()
            .await;
        match res {
            Ok(res) => {
                log::debug!("Worked!");
                let mut final_response = Response::new(Body::from(""));
                *final_response.status_mut() = res.status();
                *final_response.headers_mut() = res.headers().clone();
                final_response.headers_mut().append(
                    "Onion-Location",
                    HeaderValue::from_str(target.domain().unwrap_or("")).unwrap(),
                );
                let res_bytes = res.bytes().await?;
                *final_response.body_mut() = Body::from(res_bytes);
                track_status_code(final_response.status().as_u16().into(), "production");
                track_request_time(now.elapsed().as_secs_f64(), "production");
                Ok(final_response)
            }
            Err(err) => {
                log::debug!("Failed!");
                eprintln!("{:#?}", err);
                let mut res = Response::new(Body::from(include_str!("static/minified/502.html")));
                *res.status_mut() = StatusCode::BAD_GATEWAY;
                track_status_code(res.status().as_u16().into(), "production");
                track_request_time(now.elapsed().as_secs_f64(), "production");
                Ok(res)
            }
        }
    }
}

/// Handle a websocket connection.
async fn serve_websocket(
    websocket: HyperWebsocket,
    target: Url,
    request_url: &Uri,
) -> Result<(), Error> {
    let mut target = target;
    let target_port = target.port().unwrap_or_else(|| match target.origin() {
        url::Origin::Opaque(_) => 0,
        url::Origin::Tuple(proto, _, _) => match proto.as_str() {
            "ws" => 80,
            "wss" => 443,
            "http" => 80,
            "https" => 443,
            _ => 0,
        },
    });
    if target_port == 0 {
        return Err("Invalid protocol".into());
    }
    target
        .set_scheme(match target.origin() {
            url::Origin::Opaque(_) => panic!(),
            url::Origin::Tuple(proto, _, _) => match proto.as_str() {
                "ws" => "ws",
                "wss" => "wss",
                "http" => "ws",
                "https" => "wss",
                _ => panic!(),
            },
        })
        .expect("Invalid protocol");
    target
        .set_port(Some(target_port))
        .expect("Invalid protocol");
    target.set_path(request_url.path());
    target.set_query(request_url.query());

    let socks_client = Socks5Stream::connect(
        dotenv::var("TOR_PROXY").expect("Missing TOR_PROXY env var"),
        target.domain().unwrap().to_string(),
        target_port,
        fast_socks5::client::Config::default(),
    )
    .await?;
    let socket = socks_client.get_socket();
    let (origin_server, websocket) =
        try_join!(tokio_tungstenite::client_async(target, socket), websocket)?;
    let (write_target, read_target) = origin_server.0.split();
    let (write_client, read_client) = websocket.split();
    CONNECTED_CLIENTS.inc();
    let forwarding_result = try_join!(
        read_client.forward(write_target),
        read_target.forward(write_client)
    );
    CONNECTED_CLIENTS.dec();
    if let Err(forwarding_error) = forwarding_result {
        eprintln!("{:#?}", forwarding_error);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();
    register_custom_metrics();
    let proxy_addr: std::net::SocketAddr = dotenv::var("LISTEN")
        .expect("Missing LISTEN env var")
        .parse()?;
    let metrics_addr: std::net::SocketAddr = dotenv::var("METRICS_LISTEN")
        .expect("Missing METRICS_LISTEN env var")
        .parse()?;
    let chain_path = dotenv::var("TLS_CERT_CHAIN_PATH").expect("Missing tls cert chain path");
    let privkey_path = dotenv::var("TLS_KEY_PATH").expect("Missing tls key path");

    log::debug!("Binding to address");
    println!("Proxy listening on https://{}", proxy_addr);
    println!("Metrics listening on http://{}", metrics_addr);
    let proxy_service =
        make_service_fn(|_| async { Ok::<_, io::Error>(service_fn(handle_request)) });
    let proxy_server = hyper_from_pem_files(chain_path, privkey_path, Protocols::ALL, &proxy_addr)
        .unwrap()
        .serve(proxy_service);
    let metrics_service =
        make_service_fn(|_| async { Ok::<_, io::Error>(service_fn(metrics_handler)) });
    let metrics_server = hyper::Server::bind(&proxy_addr).serve(metrics_service);
    try_join!(proxy_server, metrics_server).expect("Listening failed");
    Ok(())
}

fn track_request_time(response_time: f64, env: &str) {
    RESPONSE_TIME_COLLECTOR
        .with_label_values(&[env])
        .observe(response_time);
}

fn track_status_code(status_code: usize, env: &str) {
    RESPONSE_CODE_COLLECTOR
            .with_label_values(&[env, &status_code.to_string(), &status_code.to_string()]);
}

async fn metrics_handler(_request: Request<Body>) -> Result<Response<Body>, Error> {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        eprintln!("could not encode custom metrics: {}", e);
    };
    let mut res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("custom metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        eprintln!("could not encode prometheus metrics: {}", e);
    };
    let res_custom = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("prometheus metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    res.push_str(&res_custom);
    Ok(Response::new(Body::from(res)))
}
