use axum::{
    extract::Form,
    http::{Response, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use dotenv::dotenv;
use reqwest::header;
use serde::Deserialize;
use serde_json::json;
use serde_json::Value;
use std::env;
use std::{collections::HashMap, net::SocketAddr};

pub use self::error::{AxumError, Result};
mod error;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    check_env_on_async_fns();

    let dsn = env::var("SENTRY_DSN").expect("Missing SENTRY_DSN");
    let _guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            ..Default::default()
        },
    ));

    let routes_all = Router::new()
        .route("/health", get(handler_healthy))
        .route("/captcha", post(handler_captcha));

    let addr = SocketAddr::from(([0, 0, 0, 0], 2121));
    println!("Listening on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(routes_all.into_make_service())
        .await
        .unwrap();

    Ok(())
}

fn check_env_on_async_fns() {
    let _ = env::var("GRECAPTCHA_SECRET_KEY").expect("GRECAPTCHA_SECRET_KEY must be set");
}

async fn handler_healthy() -> impl IntoResponse {
    let html = "Healthy";
    Html(html)
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
    let secret = env::var("GRECAPTCHA_SECRET_KEY").expect("GRECAPTCHA_SECRET_KEY must be set");
    let mut form_data = HashMap::new();
    form_data.insert("secret", &secret);
    form_data.insert("response", &form.g_recaptcha_response);

    let client = reqwest::Client::new();
    let res = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&form_data)
        .send()
        .await;

    match res {
        Ok(res) => {
            let json: Value = res.json().await.unwrap();
            if json["success"].as_bool().unwrap_or(false) {
                // continue on to do actions (i.e. send mail to info box)
                // send email
                let email_send_result =
                    send_email_based_on_site(&form.site, &form.fields_in_contact_form).await;

                match email_send_result {
                    Ok(_) => Response::builder()
                        .status(StatusCode::OK)
                        .body(json!({"message": "Captcha verification successful"}).to_string())
                        .unwrap(),
                    Err(e) => match e {
                        AxumError::SiteNotFoundError => {
                            sentry::capture_error(&e);
                            Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .body(json!({"message": "Site not found"}).to_string())
                                .unwrap()
                        }
                        _ => {
                            sentry::capture_error(&e);
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(json!({"message": "Cannot send email"}).to_string())
                                .unwrap()
                        }
                    },
                }
            } else {
                // If Error send back generic failed error
                let err = AxumError::CaptchaFailedError(json);
                sentry::capture_error(&err);
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(json!({"message": "Captcha verification failed"}).to_string())
                    .unwrap()
            }
        }
        Err(err) => {
            sentry::capture_error(&err);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(json!({"message": "Captcha verification failed"}).to_string())
                .unwrap()
        }
    }
}

async fn send_email_based_on_site(site: &str, fields: &HashMap<String, String>) -> Result<()> {
    if let Ok(api_key) = env::var(format!("{}_SENDGRID_API_KEY", site.to_ascii_uppercase())) {
        let email_to = env::var(format!("{}_EMAIL_TO", site.to_ascii_uppercase())).unwrap();
        let email_from = env::var(format!("{}_EMAIL_FROM", site.to_ascii_uppercase())).unwrap();
        let body = format!(
            "You have a new contact request! Please see details below:\n{}",
            hashmap_to_string(fields)
        );
        let subject = "New lead from your website!";

        let client = reqwest::Client::new();
        let res = client
            .post("https://api.sendgrid.com/v3/mail/send")
            .header(header::AUTHORIZATION, format!("Bearer {}", api_key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                json!({
                    "personalizations": [
                        {
                            "to": [
                                {
                                    "email": email_to
                                }
                            ],
                            "subject": subject
                        }
                    ],
                    "from": {
                        "email": email_from
                    },
                    "content": [
                        {
                            "type": "text/plain",
                            "value": body
                        }
                    ]
                })
                .to_string(),
            )
            .send()
            .await;
        match res {
            Ok(_) => Ok(()),
            Err(_) => Err(AxumError::EmailError),
        }
    } else {
        Err(AxumError::SiteNotFoundError)
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
        assert!(result.is_ok());
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
