use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use dotenv::dotenv;
use dotenv_codegen::dotenv;
use jsonwebtoken::{encode, EncodingKey, Header};
use ollama_rs::{generation::completion::request::GenerationRequest, Ollama};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // Could be username or user id
    exp: usize,
}

#[derive(Debug, Deserialize)]
struct QueryRequest {
    prompt: String,
    #[serde(default = "default_model")]
    model: String,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
}

#[derive(Debug, Serialize)]
struct QueryResponse {
    response: String,
    model: String,
    elapsed_ms: u128,
}

fn default_model() -> String {
    "deepseek-coder".to_string()
}

fn default_timeout() -> u64 {
    30
}

struct AppState {
    ollama: Ollama,
}

const JWT_SECRET: &[u8] = b"your-very-secret-key";

#[derive(sqlx::FromRow)]
struct User {
    id: i32,
    username: String,
    password_hash: String,
}

// Handler to register a new user.
#[axum::debug_handler]
async fn register_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Hash the password.
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            eprintln!("Password hashing failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    // Insert the new user into the database.
    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES ($1, $2)")
        .bind(payload.username)
        .bind(password_hash)
        .execute(&pool)
        .await;

    match result {
        Ok(_) => (StatusCode::CREATED, "User registered successfully").into_response(),
        Err(e) => {
            eprintln!("Database insertion error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to register user").into_response()
        }
    }
}

#[axum::debug_handler]
async fn login_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    // Fetch the user record from the database.
    let user = match sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash FROM users WHERE username = $1",
    )
    .bind(&payload.username)
    .fetch_one(&pool)
    .await
    {
        Ok(user) => user,
        Err(e) => {
            eprintln!("User not found or database error: {}", e);
            return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
        }
    };

    // Parse the stored password hash.
    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Failed to parse password hash: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    // Verify the provided password against the stored hash.
    if Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    // Create a JWT token that expires in 24 hours.
    let expiration = Utc::now() + chrono::Duration::hours(24);
    let claims = Claims {
        sub: user.username,
        exp: expiration.timestamp() as usize,
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Token creation error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Token creation failed").into_response();
        }
    };

    let response = AuthResponse { token };
    (StatusCode::OK, Json(response)).into_response()
}

// Handler for the query endpoint remains unchanged.
async fn query_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<QueryRequest>,
) -> Result<Json<QueryResponse>, (StatusCode, String)> {
    let start_time = std::time::Instant::now();

    let generation_request = GenerationRequest::new(request.model.clone(), request.prompt);

    // Execute query with timeout.
    let result = timeout(
        Duration::from_secs(request.timeout_secs),
        state.ollama.generate(generation_request),
    )
    .await
    .map_err(|_| (StatusCode::REQUEST_TIMEOUT, "Query timed out".to_string()))?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Ollama error: {}", e),
        )
    })?;

    let elapsed = start_time.elapsed().as_millis();

    Ok(Json(QueryResponse {
        response: result.response,
        model: request.model,
        elapsed_ms: elapsed,
    }))
}

// New health check handler.
async fn health_handler() -> (StatusCode, &'static str) {
    println!("Health check");
    (StatusCode::OK, "Healthy")
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    // Initialize Ollama client pointing to the container.
    let ollama = Ollama::new("http://ollama".to_string(), 11434);

    let shared_state = Arc::new(AppState { ollama });

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        .expect("Failed to create pool");

    let app = Router::new()
        .route("/query", post(query_handler))
        .route("/health", get(health_handler))
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .layer(Extension(pool))
        .with_state(shared_state)
        .layer(tower_http::cors::CorsLayer::permissive());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind port 3000");

    println!("Server running on http://localhost:3000");
    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}
