use axum::{
    extract::Form,
    http::{Response, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::json;
use serde_json::Value;
use std::env;
use std::{collections::HashMap, net::SocketAddr};

pub use self::error::{Error, Result};
mod error;

#[tokio::main]
async fn main() -> Result<()> {
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
    pub fields_in_contact_form: HashMap<String, Value>,
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
                println!("Success for token {}", &form.g_recaptcha_response);
                // send email
                if send_email_based_on_site(&form.site).is_ok() {
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(json!({"message": "Captcha verification successful"}).to_string())
                        .unwrap()
                } else {
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(json!({"message": "Site not found"}).to_string())
                        .unwrap()
                }
            } else {
                // If Error send back generic failed error
                println!("Error for token {}. ", &form.g_recaptcha_response);
                dbg!(&json);
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(json!({"message": "Captcha verification failed"}).to_string())
                    .unwrap()
            }
        }
        Err(_) => {
            println!("Error for token {}. ", &form.g_recaptcha_response);
            dbg!(&res);
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(json!({"message": "Captcha verification failed"}).to_string())
                .unwrap()
        }
    }
}

fn send_email_based_on_site(site: &str) -> Result<()> {
    if env::var(format!("{}_SMTP_SERVER", site.to_ascii_uppercase())).is_ok() {
        Ok(())
    } else {
        Err(Error::SiteNotFoundError)
    }
}
