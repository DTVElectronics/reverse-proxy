use cached::proc_macro::io_cached;
use core::task::{Context, Poll};
use fast_socks5::client::Socks5Stream;
use futures_util::ready;
use futures_util::StreamExt;
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream};
use hyper::service::{make_service_fn, service_fn};
use hyper::{http::HeaderValue, Body, Request, Response, Server, StatusCode, Uri};
use hyper_tungstenite::HyperWebsocket;
use lazy_static::lazy_static;
use postgrest::Postgrest;
use reverse_proxy::cache_utils::AsyncRedisCache;
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;
use std::{fs, io, sync};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::{join, try_join};
use tokio_rustls::rustls::ServerConfig;
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
    let host = request.headers().get("Host");
    if host.is_none() || host.unwrap().to_str().is_err() {
        let mut res = Response::new(Body::from("Missing host header"));
        *res.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(res);
    }
    let host = host.unwrap().to_str().unwrap();
    let target = get_target(host.to_string()).await;
    if target.is_err() {
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
        headers.append(
            "X-Forwarded-For",
            request
                .headers()
                .get("host")
                .expect("No host present!")
                .clone(),
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

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    dotenv::dotenv().ok();
    let addr: std::net::SocketAddr = dotenv::var("LISTEN")
        .expect("Missing LISTEN env var")
        .parse()?;
    println!("Listening on https://{}", addr);
    let tls_cfg = {
        let certs = load_certs(
            dotenv::var("TLS_CERT_CHAIN_PATH")
                .expect("Missing tls cert chain path")
                .as_str(),
        )?;
        let key = load_private_key(
            dotenv::var("TLS_KEY_PATH")
                .expect("Missing tls key path")
                .as_str(),
        )?;
        // Do not use client certificate authentication.
        let mut cfg = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| error(format!("{}", e)))?;
        // Configure ALPN to accept HTTP/2, HTTP/1.1 in that order.
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        sync::Arc::new(cfg)
    };

    let incoming = AddrIncoming::bind(&addr)?;
    let service = make_service_fn(|_| async { Ok::<_, io::Error>(service_fn(handle_request)) });
    Server::builder(TlsAcceptor::new(tls_cfg, incoming))
        .serve(service)
        .await?;
    Ok(())
}

enum State {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite handshaking tokio_rustls::Accept first
pub struct TlsStream {
    state: State,
}

impl TlsStream {
    fn new(stream: AddrStream, config: Arc<ServerConfig>) -> TlsStream {
        let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);
        TlsStream {
            state: State::Handshaking(accept),
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_read(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub fn new(config: Arc<ServerConfig>, incoming: AddrIncoming) -> TlsAcceptor {
        TlsAcceptor { config, incoming }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| error("failed to load certificate".into()))?;
    Ok(certs.into_iter().map(rustls::Certificate).collect())
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = io::BufReader::new(keyfile);
        rustls_pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = io::BufReader::new(keyfile);
        rustls_pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        Ok(rustls::PrivateKey(pkcs8_keys[0].clone()))
    } else {
        assert!(!rsa_keys.is_empty());
        Ok(rustls::PrivateKey(rsa_keys[0].clone()))
    }
}
