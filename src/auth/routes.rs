use crate::api_error::ApiError;
use crate::user::User;
use crate::user::UserMessage;

use actix_session::Session;
use actix_web::get;
use actix_web::post;
use actix_web::web;
use actix_web::HttpResponse;
use serde_json::json;
use uuid::Uuid;

#[post("/register")]
async fn register(user: web::Json<UserMessage>) -> Result<HttpResponse, ApiError> {
    let user = User::create(user.into_inner())?;
    Ok(HttpResponse::Ok().json(user))
}

#[post("/sign-in")]
async fn sign_in(
    credentials: web::Json<UserMessage>,
    session: Session,
) -> Result<HttpResponse, ApiError> {
    let credentials = credentials.into_inner();

    let user = User::find_by_email(credentials.email).map_err(|e| match e.status_code {
        404 => ApiError::new(401, "Credentials not valid!".to_string()),
        _ => e,
    })?;

    let is_valid = user.verify_password(credentials.password.as_bytes())?;
    if is_valid == true {
        session.set("user_id", user.id)?;
        session.renew();
        Ok(HttpResponse::Ok().json(user))
    } else {
        Err(ApiError::new(401, "Credentials not valid!".to_string()))
    }
}

#[post("/sign-out")]
async fn sign_out(session: Session) -> Result<HttpResponse, ApiError> {
    let id: Option<Uuid> = session.get("user_id")?;

    if let Some(_) = id {
        session.purge();
        Ok(HttpResponse::Ok().json(json!({ "message": "Succesfully signed out" })))
    } else {
        Err(ApiError::new(401, "Unauthorized".to_string()))
    }
}

#[get("/whoami")]
async fn who_am_i(session: Session) -> Result<HttpResponse, ApiError> {
    let id: Option<Uuid> = session.get("user_id")?;

    if let Some(id) = id {
        let user = User::find(id)?;
        Ok(HttpResponse::Ok().json(user))
    } else {
        Err(ApiError::new(401, "Unauthorized".to_string()))
    }
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(register);
    cfg.service(sign_in);
    cfg.service(sign_out);
    cfg.service(who_am_i);
}
