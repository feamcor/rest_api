#[macro_use]
extern crate log;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate diesel_migrations;

use actix_redis::RedisSession;
use actix_web::App;
use actix_web::HttpServer;
use dotenv::dotenv;
use std::env;

mod api_error;
mod auth;
mod db;
mod schema;
mod user;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    db::init();

    let redis_host = env::var("REDIS_HOST").expect("REDIS_HOST is not set");
    let redis_port = env::var("REDIS_PORT").expect("REDIS_PORT is not set");

    let api_host = env::var("API_HOST").expect("API_HOST is not set");
    let api_port = env::var("API_PORT").expect("API_PORT is not set");
    let api_server = HttpServer::new(move || {
        App::new()
            .wrap(RedisSession::new(
                format!("{}:{}", redis_host, redis_port),
                &[0; 32],
            ))
            .configure(user::init_routes)
            .configure(auth::init_routes)
    })
    .bind(format!("{}:{}", api_host, api_port))?;

    info!("Starting server...");
    api_server.run().await
}
