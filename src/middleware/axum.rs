use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::response::IntoResponse;
use axum::response::Response;
use http::Request;
use ipnet::IpNet;
use tower::{Layer, Service};

use crate::engine::TollBoothEngine;
use crate::types::{TollBoothRequest, TollBoothResult, UNKNOWN_IP};

// ---------------------------------------------------------------------------
// TollBoothLayer
// ---------------------------------------------------------------------------

/// Tower [`Layer`] that wraps a [`TollBoothEngine`] for use with axum.
///
/// Add to an axum [`Router`] with `.layer(TollBoothLayer::new(engine))`.
///
/// By default the client IP is taken from the connection peer address
/// (axum's `ConnectInfo<SocketAddr>`) and `X-Forwarded-For` / `X-Real-IP`
/// are ignored, because they are trivially spoofable by clients. If the
/// service sits behind a reverse proxy, configure
/// [`TollBoothLayer::with_trusted_proxies`] with the proxy IPs/CIDRs so
/// those headers are honoured *only* when the direct peer is trusted.
#[derive(Clone)]
pub struct TollBoothLayer {
    engine: Arc<TollBoothEngine>,
    trusted_proxies: Arc<Vec<IpNet>>,
}

impl TollBoothLayer {
    /// Create a new layer, taking ownership of the engine.
    pub fn new(engine: TollBoothEngine) -> Self {
        Self {
            engine: Arc::new(engine),
            trusted_proxies: Arc::new(Vec::new()),
        }
    }

    /// Create a new layer from a pre-existing `Arc`.
    pub fn from_arc(engine: Arc<TollBoothEngine>) -> Self {
        Self {
            engine,
            trusted_proxies: Arc::new(Vec::new()),
        }
    }

    /// Trust `X-Forwarded-For` / `X-Real-IP` only when the direct connection
    /// peer falls within one of these networks. Empty (the default) means the
    /// headers are never honoured.
    pub fn with_trusted_proxies(mut self, proxies: Vec<IpNet>) -> Self {
        self.trusted_proxies = Arc::new(proxies);
        self
    }
}

impl<S> Layer<S> for TollBoothLayer {
    type Service = TollBoothService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TollBoothService {
            engine: self.engine.clone(),
            trusted_proxies: self.trusted_proxies.clone(),
            inner,
        }
    }
}

// ---------------------------------------------------------------------------
// TollBoothService
// ---------------------------------------------------------------------------

/// Tower [`Service`] produced by [`TollBoothLayer`].
#[derive(Clone)]
pub struct TollBoothService<S> {
    engine: Arc<TollBoothEngine>,
    trusted_proxies: Arc<Vec<IpNet>>,
    inner: S,
}

impl<S> Service<Request<Body>> for TollBoothService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let engine = self.engine.clone();
        let trusted_proxies = self.trusted_proxies.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let peer = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0);
            let tb_req = extract_request(&req, peer, &trusted_proxies);

            match engine.handle(&tb_req).await {
                // -------------------------------------------------------
                // Allowed — inject headers and forward to the inner handler
                // -------------------------------------------------------
                TollBoothResult::Pass { headers, .. } | TollBoothResult::Proxy { headers, .. } => {
                    // Inject toll-booth headers into the request extensions
                    // so downstream handlers can inspect them if needed.
                    let mut req = req;

                    // SECURITY: strip the client-supplied X-Toll-Tier header
                    // so raw client input never reaches upstream. Only the
                    // server-side state returned by the engine (inserted
                    // below) may set it on the proxied request.
                    req.headers_mut().remove("x-toll-tier");

                    for (k, v) in &headers {
                        if let (Ok(name), Ok(value)) = (
                            http::header::HeaderName::from_bytes(k.as_bytes()),
                            http::header::HeaderValue::from_str(v),
                        ) {
                            req.headers_mut().insert(name, value);
                        }
                    }

                    let mut response = inner.call(req).await?;

                    // Also surface the headers on the response so the
                    // client can observe credit balance etc.
                    for (k, v) in headers {
                        if let (Ok(name), Ok(value)) = (
                            http::header::HeaderName::from_bytes(k.as_bytes()),
                            http::header::HeaderValue::from_str(&v),
                        ) {
                            response.headers_mut().insert(name, value);
                        }
                    }

                    Ok(response)
                }

                // -------------------------------------------------------
                // Challenge — short-circuit with 402
                // -------------------------------------------------------
                TollBoothResult::Challenge {
                    status,
                    headers,
                    body,
                } => {
                    let status_code = http::StatusCode::from_u16(status)
                        .unwrap_or(http::StatusCode::PAYMENT_REQUIRED);

                    let mut response = axum::Json(body).into_response();
                    *response.status_mut() = status_code;

                    for (k, v) in headers {
                        if let (Ok(name), Ok(value)) = (
                            http::header::HeaderName::from_bytes(k.as_bytes()),
                            http::header::HeaderValue::from_str(&v),
                        ) {
                            response.headers_mut().insert(name, value);
                        }
                    }

                    Ok(response)
                }

                // -------------------------------------------------------
                // Blocked — short-circuit with the engine-supplied status
                // -------------------------------------------------------
                TollBoothResult::Blocked { status, body } => {
                    let status_code = http::StatusCode::from_u16(status)
                        .unwrap_or(http::StatusCode::FORBIDDEN);
                    let mut response = axum::Json(body).into_response();
                    *response.status_mut() = status_code;
                    Ok(response)
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// extract_request helper
// ---------------------------------------------------------------------------

fn extract_request(
    req: &Request<Body>,
    peer: Option<SocketAddr>,
    trusted_proxies: &[IpNet],
) -> TollBoothRequest {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    let mut headers: HashMap<String, String> = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_string(), v.to_string());
        }
    }

    // Extract the client IP.
    //
    // SECURITY: X-Forwarded-For / X-Real-IP are client-controllable and are
    // honoured only when the direct connection peer is a configured trusted
    // proxy. Otherwise the connection peer address is used, so a client
    // cannot rotate XFF values to evade free-tier quota or spoof the IP an
    // `ip` macaroon caveat is bound to. When no peer address is available
    // at all, the IP is UNKNOWN_IP, which fails closed downstream: the
    // engine refuses free-tier grants and IP caveats cannot match it.
    let ip = match peer {
        Some(peer_addr) => {
            let peer_ip = peer_addr.ip();
            let peer_is_trusted = trusted_proxies.iter().any(|net| net.contains(&peer_ip));
            if peer_is_trusted {
                headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.split(',').next())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .or_else(|| headers.get("x-real-ip").cloned())
                    .unwrap_or_else(|| peer_ip.to_string())
            } else {
                peer_ip.to_string()
            }
        }
        None => UNKNOWN_IP.to_string(),
    };

    let tier = headers.get("x-toll-tier").cloned();

    TollBoothRequest {
        method,
        path,
        headers,
        ip,
        tier,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::{routing::get, Router};
    use http::{Request, StatusCode};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt; // for oneshot

    use crate::engine::{FreeTierConfig, TollBoothConfig, TollBoothEngine};
    use crate::macaroon::{self, RootKey};
    use crate::rails::{L402Rail, L402RailConfig};
    use crate::storage::MemoryStorage;
    use crate::types::{Currency, PricingEntry};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn test_root_key() -> RootKey {
        RootKey::from_hex(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        )
        .unwrap()
    }

    fn make_engine() -> TollBoothEngine {
        make_engine_with_free_tier(None)
    }

    fn make_engine_with_free_tier(free_requests: Option<u64>) -> TollBoothEngine {
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(MemoryStorage::new());
        let l402 = L402Rail::new(L402RailConfig {
            root_key: test_root_key(),
            storage: storage.clone(),
            default_amount: 100,
            backend: None,
            service_name: None,
        });

        let mut pricing = HashMap::new();
        pricing.insert("/api/test".to_string(), PricingEntry::Simple(100));

        TollBoothEngine::new(TollBoothConfig {
            storage,
            pricing,
            upstream: "http://localhost:8080".into(),
            root_key: Some(test_root_key()),
            rails: vec![Box::new(l402)],
            free_tier: free_requests.map(FreeTierConfig::Requests),
            ..Default::default()
        })
        .unwrap()
    }

    fn make_l402_auth_header() -> String {
        let preimage_bytes = [0xABu8; 32];
        let preimage_hex = hex::encode(preimage_bytes);
        let payment_hash = hex::encode(Sha256::digest(preimage_bytes));
        let macaroon_b64 =
            macaroon::mint_macaroon(&test_root_key(), &payment_hash, 1000, &[], Currency::Sat)
                .unwrap();
        format!("L402 {macaroon_b64}:{preimage_hex}")
    }

    fn build_app(engine: TollBoothEngine) -> Router {
        build_app_with_layer(TollBoothLayer::new(engine))
    }

    fn build_app_with_layer(layer: TollBoothLayer) -> Router {
        Router::new()
            .route("/api/test", get(|| async { "ok" }))
            .route("/free", get(|| async { "free" }))
            .layer(layer)
    }

    // -----------------------------------------------------------------------
    // Test 1: unpriced route passes through with 200
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_unpriced_passes_through() {
        let app = build_app(make_engine());

        let request = Request::builder().uri("/free").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // Test 2: priced route without auth returns 402 with WWW-Authenticate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_priced_returns_402() {
        let app = build_app(make_engine());

        let request = Request::builder()
            .uri("/api/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(
            response.headers().contains_key("www-authenticate"),
            "402 response must include WWW-Authenticate header"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3: valid L402 auth passes through with 200
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_paid_request_passes() {
        let app = build_app(make_engine());
        let auth = make_l402_auth_header();

        let request = Request::builder()
            .uri("/api/test")
            .header("authorization", auth)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // Test 4: 402 response body is valid JSON with l402 object
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_402_body_is_json() {
        let app = build_app(make_engine());

        let request = Request::builder()
            .uri("/api/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert!(
            json.get("l402").is_some(),
            "402 body must contain l402 object, got: {json}"
        );
    }

    // -----------------------------------------------------------------------
    // Security: X-Forwarded-For spoofing
    // -----------------------------------------------------------------------

    fn app_with_free_tier(n: u64, trusted: Vec<IpNet>) -> Router {
        build_app_with_layer(
            TollBoothLayer::new(make_engine_with_free_tier(Some(n)))
                .with_trusted_proxies(trusted),
        )
    }

    fn with_connect_info(mut req: Request<Body>, ip: [u8; 4]) -> Request<Body> {
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 12345))));
        req
    }

    #[tokio::test]
    async fn test_xff_ignored_when_peer_untrusted() {
        let app = app_with_free_tier(1, Vec::new()); // no trusted proxies

        // First request from peer 10.0.0.5 with a spoofed XFF: the peer's
        // own quota is used, so the free request succeeds.
        let req1 = with_connect_info(
            Request::builder()
                .uri("/api/test")
                .header("x-forwarded-for", "203.0.113.1")
                .body(Body::empty())
                .unwrap(),
            [10, 0, 0, 5],
        );
        let r1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(
            r1.status(),
            StatusCode::OK,
            "first request should pass via the peer's free-tier quota"
        );

        // Second request: same peer, rotated spoofed XFF -- must NOT grant
        // extra free-tier access.
        let req2 = with_connect_info(
            Request::builder()
                .uri("/api/test")
                .header("x-forwarded-for", "203.0.113.2")
                .body(Body::empty())
                .unwrap(),
            [10, 0, 0, 5],
        );
        let r2 = app.oneshot(req2).await.unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::PAYMENT_REQUIRED,
            "rotating X-Forwarded-For must not evade the free-tier quota"
        );
    }

    #[tokio::test]
    async fn test_xff_honoured_from_trusted_proxy() {
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let app = app_with_free_tier(1, trusted);

        // Request via trusted proxy for client 203.0.113.1: allowed.
        let req1 = with_connect_info(
            Request::builder()
                .uri("/api/test")
                .header("x-forwarded-for", "203.0.113.1")
                .body(Body::empty())
                .unwrap(),
            [10, 0, 0, 1],
        );
        let r1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK);

        // Same client IP again: its quota is exhausted.
        let req2 = with_connect_info(
            Request::builder()
                .uri("/api/test")
                .header("x-forwarded-for", "203.0.113.1")
                .body(Body::empty())
                .unwrap(),
            [10, 0, 0, 1],
        );
        let r2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::PAYMENT_REQUIRED,
            "client IP quota must be tracked via XFF behind a trusted proxy"
        );

        // A different client IP through the same proxy still gets access.
        let req3 = with_connect_info(
            Request::builder()
                .uri("/api/test")
                .header("x-forwarded-for", "203.0.113.2")
                .body(Body::empty())
                .unwrap(),
            [10, 0, 0, 1],
        );
        let r3 = app.oneshot(req3).await.unwrap();
        assert_eq!(r3.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_no_peer_info_fails_closed_for_free_tier() {
        let app = app_with_free_tier(100, Vec::new());

        // No ConnectInfo extension (e.g. a server not started with
        // into_make_service_with_connect_info): the free tier must NOT be
        // granted under a shared "unknown" bucket.
        let req = Request::builder()
            .uri("/api/test")
            .header("x-forwarded-for", "203.0.113.9")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYMENT_REQUIRED,
            "unknown peer must fail closed, not share an 'unknown' quota bucket"
        );
    }

    // -----------------------------------------------------------------------
    // Security: client-supplied X-Toll-Tier must not reach upstream
    // -----------------------------------------------------------------------

    async fn tier_echo(req: Request<Body>) -> &'static str {
        if req.headers().contains_key("x-toll-tier") {
            "present"
        } else {
            "absent"
        }
    }

    #[tokio::test]
    async fn test_inbound_toll_tier_stripped_on_passthrough() {
        let app = Router::new()
            .route("/free", get(tier_echo))
            .layer(TollBoothLayer::new(make_engine()));

        let req = Request::builder()
            .uri("/free")
            .header("x-toll-tier", "cheap")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            b"absent",
            "inbound X-Toll-Tier must be stripped before the request reaches upstream"
        );
    }

    #[tokio::test]
    async fn test_inbound_toll_tier_stripped_on_free_tier_path() {
        // Free-tier grants carry no tier header from the engine, so the
        // client-supplied header must never leak upstream here either.
        let app = Router::new()
            .route("/api/test", get(tier_echo))
            .layer(TollBoothLayer::new(make_engine_with_free_tier(Some(10))));

        let req = with_connect_info(
            Request::builder()
                .uri("/api/test")
                .header("x-toll-tier", "cheap")
                .body(Body::empty())
                .unwrap(),
            [192, 0, 2, 1],
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            b"absent",
            "inbound X-Toll-Tier must be stripped on free-tier proxying"
        );
    }

    // -----------------------------------------------------------------------
    // Security: engine-supplied Blocked status is honoured
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_blocked_status_from_engine_is_honoured() {
        use crate::storage::memory::test_util::FlakyStorage;

        // Storage whose debit always fails -> engine blocks with 500.
        let storage: Arc<dyn crate::storage::StorageBackend> =
            Arc::new(FlakyStorage::new(true, false));
        let l402 = L402Rail::new(L402RailConfig {
            root_key: test_root_key(),
            storage: storage.clone(),
            default_amount: 100,
            backend: None,
            service_name: None,
        });
        let mut pricing = HashMap::new();
        pricing.insert("/api/test".to_string(), PricingEntry::Simple(100));
        let engine = TollBoothEngine::new(TollBoothConfig {
            storage,
            pricing,
            upstream: "http://localhost:8080".into(),
            root_key: Some(test_root_key()),
            rails: vec![Box::new(l402)],
            free_tier: None,
            ..Default::default()
        })
        .unwrap();
        let app = build_app(engine);

        let auth = make_l402_auth_header();
        let req = Request::builder()
            .uri("/api/test")
            .header("authorization", auth)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "infrastructure failure must surface as 500, not a free pass or 403"
        );
    }
}
