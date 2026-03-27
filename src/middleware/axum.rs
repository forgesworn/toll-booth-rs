use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::response::IntoResponse;
use axum::response::Response;
use http::Request;
use tower::{Layer, Service};

use crate::engine::TollBoothEngine;
use crate::types::{TollBoothRequest, TollBoothResult};

// ---------------------------------------------------------------------------
// TollBoothLayer
// ---------------------------------------------------------------------------

/// Tower [`Layer`] that wraps a [`TollBoothEngine`] for use with axum.
///
/// Add to an axum [`Router`] with `.layer(TollBoothLayer::new(engine))`.
#[derive(Clone)]
pub struct TollBoothLayer {
    engine: Arc<TollBoothEngine>,
}

impl TollBoothLayer {
    /// Create a new layer, taking ownership of the engine.
    pub fn new(engine: TollBoothEngine) -> Self {
        Self {
            engine: Arc::new(engine),
        }
    }

    /// Create a new layer from a pre-existing `Arc`.
    pub fn from_arc(engine: Arc<TollBoothEngine>) -> Self {
        Self { engine }
    }
}

impl<S> Layer<S> for TollBoothLayer {
    type Service = TollBoothService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TollBoothService {
            engine: self.engine.clone(),
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
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let tb_req = extract_request(&req);

            match engine.handle(&tb_req).await {
                // -------------------------------------------------------
                // Allowed — inject headers and forward to the inner handler
                // -------------------------------------------------------
                TollBoothResult::Pass { headers, .. } | TollBoothResult::Proxy { headers, .. } => {
                    // Inject toll-booth headers into the request extensions
                    // so downstream handlers can inspect them if needed.
                    let mut req = req;
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
                // Blocked — short-circuit with 403
                // -------------------------------------------------------
                TollBoothResult::Blocked { body, .. } => {
                    let mut response = axum::Json(body).into_response();
                    *response.status_mut() = http::StatusCode::FORBIDDEN;
                    Ok(response)
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// extract_request helper
// ---------------------------------------------------------------------------

fn extract_request(req: &Request<Body>) -> TollBoothRequest {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    let mut headers: HashMap<String, String> = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_string(), v.to_string());
        }
    }

    // Extract IP: prefer X-Forwarded-For (first entry), then X-Real-IP.
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| headers.get("x-real-ip").cloned())
        .unwrap_or_else(|| "unknown".to_string());

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

    use crate::engine::{TollBoothConfig, TollBoothEngine};
    use crate::macaroon;
    use crate::rails::{L402Rail, L402RailConfig};
    use crate::storage::MemoryStorage;
    use crate::types::{Currency, PricingEntry};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn test_root_key() -> String {
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string()
    }

    fn make_engine() -> TollBoothEngine {
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
            root_key: test_root_key(),
            rails: vec![Box::new(l402)],
            free_tier: None,
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
        Router::new()
            .route("/api/test", get(|| async { "ok" }))
            .route("/free", get(|| async { "free" }))
            .layer(TollBoothLayer::new(engine))
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
}
