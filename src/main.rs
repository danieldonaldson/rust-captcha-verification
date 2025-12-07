use axum::{
    extract::Form,
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use dotenv::dotenv;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::{collections::HashMap, net::SocketAddr};
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;

pub use self::error::{AxumError, Result};
mod error;

lazy_static! {
    static ref HTTP_CLIENT: reqwest::Client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to create HTTP client");

    static ref GRECAPTCHA_SECRET_KEY: String = env::var("GRECAPTCHA_SECRET_KEY")
        .expect("GRECAPTCHA_SECRET_KEY must be set");

    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).expect("Failed to compile email regex");

    static ref SITE_NAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_-]+$")
        .expect("Failed to compile site name regex");
}

#[derive(Serialize)]
struct JsonResponse {
    message: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    // Force initialization of lazy statics to validate env vars early
    lazy_static::initialize(&GRECAPTCHA_SECRET_KEY);
    lazy_static::initialize(&HTTP_CLIENT);

    let dsn = env::var("SENTRY_DSN").expect("Missing SENTRY_DSN");
    let _guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            ..Default::default()
        },
    ));

    // Configure CORS - specify allowed origins from environment variable
    let allowed_origins = env::var("ALLOWED_ORIGINS")
        .expect("ALLOWED_ORIGINS environment variable must be set");

    let origins: Vec<HeaderValue> = allowed_origins
        .split(',')
        .filter_map(|origin| origin.trim().parse().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
        ])
        .allow_credentials(true);

    // Limit request body size to 1MB to prevent abuse
    let routes_all = Router::new()
        .route("/health", get(handler_healthy))
        .route("/captcha", post(handler_captcha))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(1024 * 1024));

    let addr = SocketAddr::from(([0, 0, 0, 0], 2121));
    println!("Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| {
            eprintln!("Failed to bind to address {}: {}", addr, e);
            AxumError::ServerError(e.to_string())
        })?;

    axum::serve(listener, routes_all)
        .await
        .map_err(|e| {
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

#[derive(Deserialize, Debug)]
struct CaptchaForm {
    #[serde(rename = "g-recaptcha-response")]
    g_recaptcha_response: String,
    site: String,
    #[serde(flatten)]
    pub fields_in_contact_form: HashMap<String, String>,
}

async fn handler_captcha(Form(form): Form<CaptchaForm>) -> impl IntoResponse {
    // Validate site name
    if !SITE_NAME_REGEX.is_match(&form.site) {
        return (
            StatusCode::BAD_REQUEST,
            Json(JsonResponse {
                message: "Invalid site name format".to_string(),
            }),
        )
            .into_response();
    }

    // Validate email if present in fields
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

    // Validate captcha response is not empty
    if form.g_recaptcha_response.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(JsonResponse {
                message: "Captcha response is required".to_string(),
            }),
        )
            .into_response();
    }

    let mut form_data = HashMap::new();
    form_data.insert("secret", GRECAPTCHA_SECRET_KEY.as_str());
    form_data.insert("response", &form.g_recaptcha_response);

    let res = match HTTP_CLIENT
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&form_data)
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

    if json["success"].as_bool().unwrap_or(false) {
        match send_email_based_on_site(&form.site, &form.fields_in_contact_form).await {
            Ok(_) => (
                StatusCode::OK,
                Json(JsonResponse {
                    message: "Captcha verification successful".to_string(),
                }),
            )
                .into_response(),
            Err(e) => {
                sentry::capture_error(&e);
                let (status, message) = match &e {
                    AxumError::SiteNotFoundError => (StatusCode::UNAUTHORIZED, "Site not found".to_string()),
                    AxumError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "Cannot send email".to_string()),
                };
                (status, Json(JsonResponse {
                    message,
                }))
                    .into_response()
            }
        }
    } else {
        let err = AxumError::CaptchaFailedError(json);
        sentry::capture_error(&err);
        (
            StatusCode::BAD_REQUEST,
            Json(JsonResponse {
                message: "Captcha verification failed".to_string(),
            }),
        )
            .into_response()
    }
}

async fn send_email_based_on_site(site: &str, fields: &HashMap<String, String>) -> Result<()> {
    let site_upper = site.to_ascii_uppercase();

    let api_key = env::var(format!("{}_SENDGRID_API_KEY", site_upper))
        .map_err(|_| AxumError::SiteNotFoundError)?;

    let email_to = env::var(format!("{}_EMAIL_TO", site_upper))
        .map_err(|_| AxumError::SiteNotFoundError)?;

    let email_from = env::var(format!("{}_EMAIL_FROM", site_upper))
        .map_err(|_| AxumError::SiteNotFoundError)?;

    // Validate email addresses
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

    let res = HTTP_CLIENT
        .post("https://api.sendgrid.com/v3/mail/send")
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", api_key))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&json!({
            "personalizations": [{
                "to": [{"email": email_to}],
                "subject": subject
            }],
            "from": {"email": email_from},
            "content": [{
                "type": "text/plain",
                "value": body
            }]
        }))
        .send()
        .await
        .map_err(|e| {
            eprintln!("Failed to send email: {}", e);
            AxumError::EmailError
        })?;

    if res.status().is_success() {
        Ok(())
    } else {
        eprintln!("SendGrid error: status={}, body={:?}", res.status(), res.text().await);
        Err(AxumError::EmailError)
    }
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

    fn setup_env() {
        dotenv::from_filename(".env.testing").ok();
    }
    #[tokio::test]
    async fn test_send_email_based_on_site() {
        setup_env();
        let site = "donaldson_africa";
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Test Name".to_string());
        fields.insert("email".to_string(), "test@example.com".to_string());
        fields.insert("message".to_string(), "Test message".to_string());

        // Call the function being tested
        let result = send_email_based_on_site(site, &fields).await;

        // Assert that the result is as expected
        match result {
            Ok(_) => {},
            Err(e) => {
                eprintln!("Test failed with error: {:?}", e);
                panic!("Expected Ok, got Err: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_send_email_based_on_site_fails() {
        setup_env();
        // Set up test data
        let site = "incorrect site";
        let fields = HashMap::new();

        // Call the function being tested
        let result = send_email_based_on_site(site, &fields).await;

        // Assert that the result is as expected
        match result {
            Ok(_) => panic!("expected error"),
            Err(AxumError::SiteNotFoundError) => {}
            Err(_) => panic!("wrong error"),
        }
    }
}
