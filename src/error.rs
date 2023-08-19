use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use serde_json::Value;
use std::error::Error;
use std::fmt;

pub type Result<T> = core::result::Result<T, AxumError>;

#[derive(Debug)]
pub enum AxumError {
    SiteNotFoundError,
    EmailError,
    CaptchaFailedError(Value),
}

impl IntoResponse for AxumError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response()
    }
}

impl Error for AxumError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for AxumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AxumError::SiteNotFoundError => write!(f, "Site not found"),
            AxumError::EmailError => write!(f, "Email error"),
            AxumError::CaptchaFailedError(json) => {
                write!(f, "Captcha failed error. Response: {}", json)
            }
        }
    }
}
