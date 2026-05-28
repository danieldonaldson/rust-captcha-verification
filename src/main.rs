use async_trait::async_trait;
use axum::{
    extract::{Form, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use dotenv::dotenv;
use lazy_static::lazy_static;
use regex::Regex;
use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::Resend;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;

pub use self::error::{AxumError, Result};
mod error;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).expect("Failed to compile email regex");

    static ref SITE_NAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_-]+$")
        .expect("Failed to compile site name regex");
}

#[async_trait]
trait EmailSender: Send + Sync {
    async fn send(&self, api_key: &str, from: String, to: String, subject: &str, body: &str) -> Result<()>;
}

struct ResendEmailSender;

#[async_trait]
impl EmailSender for ResendEmailSender {
    async fn send(&self, api_key: &str, from: String, to: String, subject: &str, body: &str) -> Result<()> {
        let resend = Resend::new(api_key);
        let email = CreateEmailBaseOptions::new(from, [to], subject).with_text(body);
        resend.emails.send(email).await.map_err(|e| {
            eprintln!("Resend email error: {}", e);
            AxumError::ResendError(format!("Failed to send email: {}", e))
        })?;
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    http_client: reqwest::Client,
    email_sender: Arc<dyn EmailSender>,
    recaptcha_api_base: String,
    google_api_key: String,
    google_project_id: String,
    resend_api_key: String,
}

#[derive(Serialize)]
struct JsonResponse {
    message: String,
}

#[derive(Deserialize, Debug)]
struct CaptchaForm {
    #[serde(rename = "g-recaptcha-response")]
    g_recaptcha_response: String,
    site: String,
    #[serde(flatten)]
    pub fields_in_contact_form: HashMap<String, String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let google_api_key = env::var("GOOGLE_ENTERPRISE_API_KEY")
        .expect("GOOGLE_ENTERPRISE_API_KEY must be set");
    let google_project_id = env::var("GOOGLE_PROJECT_ID")
        .expect("GOOGLE_PROJECT_ID must be set");
    let resend_api_key = env::var("RESEND_API_KEY")
        .expect("RESEND_API_KEY must be set");

    let dsn = env::var("SENTRY_DSN").expect("Missing SENTRY_DSN");
    let _guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            ..Default::default()
        },
    ));

    let allowed_origins =
        env::var("ALLOWED_ORIGINS").expect("ALLOWED_ORIGINS environment variable must be set");

    println!("Allowed origins from env: {}", allowed_origins);

    let origins: Vec<HeaderValue> = allowed_origins
        .split(',')
        .filter_map(|origin| {
            let trimmed = origin.trim();
            match trimmed.parse::<HeaderValue>() {
                Ok(val) => {
                    println!("Added allowed origin: {}", trimmed);
                    Some(val)
                }
                Err(e) => {
                    eprintln!("Failed to parse origin '{}': {}", trimmed, e);
                    None
                }
            }
        })
        .collect();

    if origins.is_empty() {
        panic!("No valid origins were parsed from ALLOWED_ORIGINS");
    }

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
        .allow_credentials(true);

    let state = Arc::new(AppState {
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client"),
        email_sender: Arc::new(ResendEmailSender),
        recaptcha_api_base: "https://recaptchaenterprise.googleapis.com".to_string(),
        google_api_key,
        google_project_id,
        resend_api_key,
    });

    let routes_all = Router::new()
        .route("/health", get(handler_healthy))
        .route("/captcha", post(handler_captcha))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 2121));
    println!("Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        eprintln!("Failed to bind to address {}: {}", addr, e);
        AxumError::ServerError(e.to_string())
    })?;

    axum::serve(listener, routes_all).await.map_err(|e| {
        eprintln!("Server error: {}", e);
        AxumError::ServerError(e.to_string())
    })?;

    Ok(())
}

async fn handler_healthy() -> impl IntoResponse {
    Json(JsonResponse {
        message: "Healthy".to_string(),
    })
}

async fn handler_captcha(
    State(state): State<Arc<AppState>>,
    Form(form): Form<CaptchaForm>,
) -> impl IntoResponse {
    if !SITE_NAME_REGEX.is_match(&form.site) {
        return (
            StatusCode::BAD_REQUEST,
            Json(JsonResponse {
                message: "Invalid site name format".to_string(),
            }),
        )
            .into_response();
    }

    if let Some(email) = form.fields_in_contact_form.get("email") {
        if !EMAIL_REGEX.is_match(email) {
            return (
                StatusCode::BAD_REQUEST,
                Json(JsonResponse {
                    message: "Invalid email format".to_string(),
                }),
            )
                .into_response();
        }
    }

    if form.g_recaptcha_response.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(JsonResponse {
                message: "Captcha response is required".to_string(),
            }),
        )
            .into_response();
    }

    let site_upper = form.site.to_ascii_uppercase();
    let site_key = match env::var(format!("{}_RECAPTCHA_SITE_KEY", site_upper)) {
        Ok(key) => key,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(JsonResponse {
                    message: "Site not found or not configured".to_string(),
                }),
            )
                .into_response();
        }
    };

    let request_body = json!({
        "event": {
            "token": form.g_recaptcha_response,
            "siteKey": site_key,
        }
    });

    let url = format!(
        "{}/v1/projects/{}/assessments?key={}",
        state.recaptcha_api_base, state.google_project_id, state.google_api_key
    );

    let res = match state
        .http_client
        .post(&url)
        .json(&request_body)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            sentry::capture_error(&err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(JsonResponse {
                    message: "Captcha verification failed".to_string(),
                }),
            )
                .into_response();
        }
    };

    let json: Value = match res.json().await {
        Ok(j) => j,
        Err(err) => {
            sentry::capture_error(&err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(JsonResponse {
                    message: "Failed to parse captcha response".to_string(),
                }),
            )
                .into_response();
        }
    };

    let is_valid = json["tokenProperties"]["valid"].as_bool().unwrap_or(false);

    if is_valid {
        println!("Captcha verification succeeded for site: {}", form.site);
        match send_email_based_on_site(
            state.email_sender.as_ref(),
            &state.resend_api_key,
            &form.site,
            &form.fields_in_contact_form,
        )
        .await
        {
            Ok(_) => {
                println!("Email sent successfully for site: {}", form.site);
                (
                    StatusCode::OK,
                    Json(JsonResponse {
                        message: "Captcha verification successful".to_string(),
                    }),
                )
                    .into_response()
            }
            Err(e) => {
                eprintln!("Email send failed for site '{}': {}", form.site, e);
                sentry::capture_error(&e);
                let (status, message) = match &e {
                    AxumError::SiteNotFoundError => {
                        (StatusCode::UNAUTHORIZED, "Site not found".to_string())
                    }
                    AxumError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
                    _ => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Cannot send email".to_string(),
                    ),
                };
                (status, Json(JsonResponse { message })).into_response()
            }
        }
    } else {
        eprintln!(
            "Captcha verification failed for site '{}'. Response: {}",
            form.site, json
        );
        let err = AxumError::CaptchaFailedError(json.clone());
        sentry::capture_error(&err);

        let error_msg = json["tokenProperties"]["invalidReason"]
            .as_str()
            .unwrap_or("Unknown error");

        (
            StatusCode::BAD_REQUEST,
            Json(JsonResponse {
                message: format!("Captcha verification failed: {}", error_msg),
            }),
        )
            .into_response()
    }
}

async fn send_email_based_on_site(
    email_sender: &dyn EmailSender,
    resend_api_key: &str,
    site: &str,
    fields: &HashMap<String, String>,
) -> Result<()> {
    let site_upper = site.to_ascii_uppercase();

    let email_to =
        env::var(format!("{}_EMAIL_TO", site_upper)).map_err(|_| AxumError::SiteNotFoundError)?;

    let email_from =
        env::var(format!("{}_EMAIL_FROM", site_upper)).map_err(|_| AxumError::SiteNotFoundError)?;

    if !EMAIL_REGEX.is_match(&email_to) {
        return Err(AxumError::ValidationError(format!(
            "Invalid recipient email: {}",
            email_to
        )));
    }

    if !EMAIL_REGEX.is_match(&email_from) {
        return Err(AxumError::ValidationError(format!(
            "Invalid sender email: {}",
            email_from
        )));
    }

    let body = format!(
        "You have a new contact request! Please see details below:\n{}",
        hashmap_to_string(fields)
    );
    let subject = "New lead from your website!";

    email_sender
        .send(resend_api_key, email_from, email_to, subject, &body)
        .await
}

fn hashmap_to_string(map: &HashMap<String, String>) -> String {
    let mut result = String::new();
    for (key, value) in map {
        result.push_str(&format!("{}: {}\n", key, value));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serial_test::serial;
    use tower::ServiceExt;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct MockEmailSender {
        should_fail: bool,
    }

    #[async_trait]
    impl EmailSender for MockEmailSender {
        async fn send(
            &self,
            _api_key: &str,
            _from: String,
            _to: String,
            _subject: &str,
            _body: &str,
        ) -> Result<()> {
            if self.should_fail {
                Err(AxumError::ResendError("mock failure".to_string()))
            } else {
                Ok(())
            }
        }
    }

    fn make_app(email_sender: Arc<dyn EmailSender>, recaptcha_base: &str) -> Router {
        let state = Arc::new(AppState {
            http_client: reqwest::Client::new(),
            email_sender,
            recaptcha_api_base: recaptcha_base.to_string(),
            google_api_key: "test-google-key".to_string(),
            google_project_id: "test-project".to_string(),
            resend_api_key: "test-resend-key".to_string(),
        });
        Router::new()
            .route("/health", get(handler_healthy))
            .route("/captcha", post(handler_captcha))
            .with_state(state)
    }

    // Sets per-site env vars needed by send_email_based_on_site and handler_captcha.
    // Tests using this must be marked #[serial] to avoid races on env vars.
    fn set_site_env_vars(site_upper: &str) {
        unsafe {
            env::set_var(
                format!("{}_RECAPTCHA_SITE_KEY", site_upper),
                "test-site-key",
            );
            env::set_var(format!("{}_EMAIL_TO", site_upper), "to@example.com");
            env::set_var(format!("{}_EMAIL_FROM", site_upper), "from@example.com");
        }
    }

    #[tokio::test]
    async fn test_health() {
        let app = make_app(
            Arc::new(MockEmailSender { should_fail: false }),
            "http://unused",
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invalid_site_name() {
        let app = make_app(
            Arc::new(MockEmailSender { should_fail: false }),
            "http://unused",
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/captcha")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("g-recaptcha-response=token&site=invalid+site"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_empty_captcha_token() {
        let app = make_app(
            Arc::new(MockEmailSender { should_fail: false }),
            "http://unused",
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/captcha")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("g-recaptcha-response=&site=mysite"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invalid_email_field() {
        let app = make_app(
            Arc::new(MockEmailSender { should_fail: false }),
            "http://unused",
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/captcha")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "g-recaptcha-response=token&site=mysite&email=notanemail",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_unconfigured_site() {
        let app = make_app(
            Arc::new(MockEmailSender { should_fail: false }),
            "http://unused",
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/captcha")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "g-recaptcha-response=token&site=unregisteredsite99999",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[serial]
    async fn test_valid_captcha_sends_email() {
        set_site_env_vars("TESTSITE");
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/v1/projects/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tokenProperties": { "valid": true }
            })))
            .mount(&mock_server)
            .await;

        let app = make_app(
            Arc::new(MockEmailSender { should_fail: false }),
            &mock_server.uri(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/captcha")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("g-recaptcha-response=valid-token&site=testsite"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_captcha_token() {
        set_site_env_vars("TESTSITE");
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/v1/projects/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tokenProperties": { "valid": false, "invalidReason": "EXPIRED" }
            })))
            .mount(&mock_server)
            .await;

        let app = make_app(
            Arc::new(MockEmailSender { should_fail: false }),
            &mock_server.uri(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/captcha")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "g-recaptcha-response=expired-token&site=testsite",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[serial]
    async fn test_email_send_failure_returns_500() {
        set_site_env_vars("TESTSITE");
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/v1/projects/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "tokenProperties": { "valid": true }
            })))
            .mount(&mock_server)
            .await;

        let app = make_app(
            Arc::new(MockEmailSender { should_fail: true }),
            &mock_server.uri(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/captcha")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("g-recaptcha-response=valid-token&site=testsite"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_send_email_unconfigured_site() {
        let sender = MockEmailSender { should_fail: false };
        let result =
            send_email_based_on_site(&sender, "fake-key", "no_such_site_xyz", &HashMap::new())
                .await;
        assert!(matches!(result, Err(AxumError::SiteNotFoundError)));
    }
}
