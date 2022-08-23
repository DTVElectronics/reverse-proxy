use cached::proc_macro::io_cached;
use fast_socks5::client::Socks5Stream;
use futures_util::StreamExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::{http::HeaderValue, Body, Request, Response, StatusCode, Uri};
use hyper_tungstenite::HyperWebsocket;
use lazy_static::lazy_static;
use postgrest::Postgrest;
use reverse_proxy::AsyncRedisCache;
use serde::Deserialize;
use simple_hyper_server_tls::{hyper_from_pem_files, Protocols};
use std::io;
use std::vec::Vec;
use thiserror::Error;
use tokio::{join, try_join};
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
        .build()
        .expect("Failed to generated request client!");
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
    let client = Postgrest::new(url).insert_header("apikey", admin_key);
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
        if data.is_err() {
            Err(LoadingTargetError::SupabaseError(
                data.unwrap_err().to_string(),
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
    log::debug!("Received request!");
    let host = request.uri().host();
    let real_host: &str;
    if host.is_none() {
        let host = request.headers().get("host");
        if host.is_none() {
            let mut res = Response::new(Body::from("Missing host header"));
            *res.status_mut() = StatusCode::BAD_REQUEST;
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
        *res.status_mut() = StatusCode::NOT_FOUND;
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
        headers.append(
            "X-Forwarded-For",
            HeaderValue::from_str(real_host).expect("Failed to turn host into a header"),
        );
        headers.append(
            "X-Forwarded-Proto",
            HeaderValue::from_str(request_url.scheme_str().unwrap_or("https"))
                .expect("Invalid URL"),
        );
        target.set_path(request_url.path());
        target.set_query(request_url.query());
        let res = REQWEST_CLIENT
            .request(request.method().clone(), target.clone())
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
                Ok(final_response)
            }
            Err(err) => {
                log::debug!("Failed!");
                eprintln!("{:#?}", err);
                let mut res = Response::new(Body::from(include_str!("static/minified/502.html")));
                *res.status_mut() = StatusCode::BAD_GATEWAY;
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
        join!(tokio_tungstenite::client_async(target, socket), websocket);
    let (write_target, read_target) = origin_server?.0.split();
    let (write_client, read_client) = websocket?.split();
    let forwarding_result = try_join!(
        read_client.forward(write_target),
        read_target.forward(write_client)
    );
    if let Err(forwarding_error) = forwarding_result {
        eprintln!("{:#?}", forwarding_error);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();
    let addr: std::net::SocketAddr = dotenv::var("LISTEN")
        .expect("Missing LISTEN env var")
        .parse()?;
    let chain_path = dotenv::var("TLS_CERT_CHAIN_PATH").expect("Missing tls cert chain path");
    let privkey_path = dotenv::var("TLS_KEY_PATH").expect("Missing tls key path");
    log::debug!("Binding to address");
    println!("Listening on https://{}", addr);
    let service = make_service_fn(|_| async { Ok::<_, io::Error>(service_fn(handle_request)) });
    hyper_from_pem_files(chain_path, privkey_path, Protocols::ALL, &addr)
        .unwrap()
        .serve(service)
        .await?;
    Ok(())
}
