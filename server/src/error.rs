use axum::{Json, http::StatusCode, response::IntoResponse};
use tunnelbridge_protocol::ApiError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, code, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required".into(),
            ),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "Forbidden".into()),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "Not found".into()),
            Self::Conflict(message) => (StatusCode::CONFLICT, "conflict", message),
            Self::Internal(error) => {
                tracing::error!(error = %error, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Internal server error".into(),
                )
            }
        };
        (
            status,
            Json(ApiError {
                code: code.into(),
                message,
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        Self::Internal(value.into())
    }
}
