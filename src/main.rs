use fast_socks5::client::Socks5Stream;
use fast_socks5::Result;
use futures::stream::StreamExt;
use hyper::{Body, Request, Response, StatusCode, Uri, http::HeaderValue};
use hyper_tungstenite::HyperWebsocket;
use std::{collections::HashMap, convert::Infallible};
use tokio::try_join;
use url::Url;
use lazy_static::lazy_static;
use cached::proc_macro::cached;

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

lazy_static! {
    static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::builder().proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050").expect("tor proxy should be there")).build().expect("Failed to generated request client!");
}

#[cached(time = 10800, sync_writes = true)]
async fn get_target(host: String) -> Option<Url> {
    let mut targets = HashMap::<String, Url>::new();
    targets.insert(
        "localhost:3000".to_string(),
        Url::parse("http://yibzxq3jdqyfjzwgatd3fqihswtrdunjdnlbmb6v6yii5g2ghntbfkad.onion").unwrap(),
    );
    return targets.remove(&host);
}
/// Handle a HTTP or WebSocket request.
async fn handle_request(mut request: Request<Body>) -> Result<Response<Body>, Error> {
    let host = request.headers().get("Host");
    if host.is_none() || host.unwrap().to_str().is_err() {
        let mut res = Response::new(Body::from("Missing host header"));
        *res.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(res);
    }
    let host = host.unwrap().to_str().unwrap();
    let target = get_target(host.to_string()).await;
    if target.is_none() {
        let mut res = Response::new(Body::from(include_str!("static/minified/404.html")));
        *res.status_mut() = StatusCode::NOT_FOUND;
        return Ok(res);
    }
    let mut target = target.unwrap().clone();
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
        let request_url = request.uri();
        let mut headers = request.headers().clone();
        headers.append("X-Forwarded-For", request.headers().get("host").expect("No host present!").clone());
        headers.append("X-Forwarded-Proto", HeaderValue::from_str(request_url.scheme_str().unwrap_or("https")).expect("Invalid URL"));
        target.set_path(request_url.path());
        target.set_query(request_url.query());
        let res = REQWEST_CLIENT.request(request.method().clone(), target.clone()).body(reqwest::Body::from(request.into_body())).send().await;
        match res {
            Ok(res) => {
                let mut final_response = Response::new(Body::from(""));
                *final_response.status_mut() = res.status();
                *final_response.headers_mut() = res.headers().clone();
                final_response.headers_mut().append("Onion-Location", HeaderValue::from_str(target.domain().unwrap_or("")).unwrap());
                let res_bytes = res.bytes().await?;
                *final_response.body_mut() = Body::from(res_bytes);
                Ok(final_response)
                
            },
            Err(err) => {
                eprintln!("{:#?}", err);
                let mut res = Response::new(Body::from(include_str!("static/minified/502.html")));
                *res.status_mut() = StatusCode::BAD_GATEWAY;
                Ok(res)
            },
        }
    }
}

/// Handle a websocket connection.
async fn serve_websocket(websocket: HyperWebsocket, target: Url, request_url: &Uri) -> Result<(), Error> {
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
    target.set_scheme(match target.origin() {
        url::Origin::Opaque(_) => panic!(),
        url::Origin::Tuple(proto, _, _) => match proto.as_str() {
            "ws" => "ws",
            "wss" => "wss",
            "http" => "ws",
            "https" => "wss",
            _ => panic!(),
        },
    }).expect("Invalid protocol");
    target.set_port(Some(target_port)).expect("Invalid protocol");
    target.set_path(request_url.path());
    target.set_query(request_url.query());
    
    let socks_client = Socks5Stream::connect(
        "127.0.0.1:9050",
        target.domain().unwrap().to_string(),
        target_port,
        fast_socks5::client::Config::default(),
    )
    .await?;
    let socket = socks_client.get_socket();
    let origin_server =
        tokio_tungstenite::client_async(target, socket)
            .await?.0;
    let websocket = websocket.await?;
    let (write_target, read_target) = origin_server.split();
    let (write_client, read_client) = websocket.split();
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
    let addr: std::net::SocketAddr = "127.0.0.1:3000".parse()?;
    println!("Listening on http://{}", addr);
    hyper::Server::bind(&addr)
        .serve(hyper::service::make_service_fn(|_connection| async {
            Ok::<_, Infallible>(hyper::service::service_fn(handle_request))
        }))
        .await?;
    Ok(())
}
