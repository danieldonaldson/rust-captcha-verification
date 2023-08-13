use axum::{
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use std::net::SocketAddr;

pub use self::error::{Error, Result};
mod error;

#[tokio::main]
async fn main() -> Result<()> {
    let routes_all = Router::new().route("/health", get(handler_healthy));

    let addr = SocketAddr::from(([127, 0, 0, 1], 2121));
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
