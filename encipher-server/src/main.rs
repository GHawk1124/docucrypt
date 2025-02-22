use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    extract::{Extension, Json, State},
    http::{HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post, put},
    Router,
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use ollama_rs::{generation::completion::request::GenerationRequest, Ollama};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tower_http::cors::CorsLayer;

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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String, // username
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

// Registration handler
#[axum::debug_handler]
async fn register_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            eprintln!("Password hashing failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES ($1, $2)")
        .bind(payload.username)
        .bind(password_hash)
        .execute(&pool)
        .await;

    match result {
        Ok(_) => (StatusCode::CREATED, "User registered successfully"),
        Err(e) => {
            eprintln!("Database insertion error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to register user")
        }
    }
}

// Login handler
#[axum::debug_handler]
async fn login_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
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

    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Failed to parse password hash: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    if Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

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

// Query handler (protected route)
// It extracts the JWT claims from the request's extensions.
async fn query_handler(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    Json(request): Json<QueryRequest>,
) -> Result<Json<QueryResponse>, (StatusCode, String)> {
    println!("Authenticated as: {}", claims.sub);

    let start_time = std::time::Instant::now();
    let generation_request = GenerationRequest::new(request.model.clone(), request.prompt);

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

// Health check handler
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "Healthy")
}

/// Middleware that checks for a valid JWT in the Authorization header.
/// On success, it attaches the extracted `Claims` to the request's extensions.
async fn jwt_auth_middleware(
    mut req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Missing Authorization header".to_string(),
            )
        })?;
    let auth_str = auth_header.to_str().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid Authorization header".to_string(),
        )
    })?;

    if !auth_str.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid Authorization scheme".to_string(),
        ));
    }
    let token = auth_str.trim_start_matches("Bearer ").trim();

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default(),
    )
    .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".to_string()))?;

    // Attach claims to request extensions for later extraction.
    req.extensions_mut().insert(token_data.claims);

    Ok(next.run(req).await)
}

// Add clearance update handler
#[derive(Deserialize)]
struct UpdateUserClearanceRequest {
    username: String,
    group_id: i32,
    new_clearance: String,
}

fn is_valid_clearance(clearance: &str) -> bool {
    matches!(clearance, "UNCLASSIFIED" | "CUI" | "SECRET" | "TOPSECRET")
}

#[axum::debug_handler]
async fn update_user_clearance_handler(
    Extension(claims): Extension<Claims>,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<UpdateUserClearanceRequest>,
) -> impl IntoResponse {
    // Validate clearance level
    if !is_valid_clearance(&payload.new_clearance) {
        return (StatusCode::BAD_REQUEST, "Invalid clearance level").into_response();
    }

    // Check if the requesting user is an admin of this specific group
    let is_admin = sqlx::query(
        "SELECT EXISTS (
            SELECT 1 FROM groups 
            WHERE id = $1 
            AND $2 = ANY(admins)
        )",
    )
    .bind(payload.group_id)
    .bind(&claims.sub)
    .fetch_one(&pool)
    .await;

    match is_admin {
        Ok(row) => {
            let exists: bool = row.get::<bool, _>("exists");
            if !exists {
                return (
                    StatusCode::FORBIDDEN,
                    "Not authorized to update clearance level for this group",
                )
                    .into_response();
            }
        }
        Err(e) => {
            eprintln!("Database error checking admin status: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    // Start a transaction
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Failed to start transaction: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    // Remove from all clearance arrays first
    let remove_query = "
        UPDATE groups 
        SET 
            unclassified_clearance = array_remove(unclassified_clearance, $1),
            cui_clearance = array_remove(cui_clearance, $1),
            secret_clearance = array_remove(secret_clearance, $1),
            topsecret_clearance = array_remove(topsecret_clearance, $1)
        WHERE id = $2";

    let result = sqlx::query(remove_query)
        .bind(&payload.username) // Remove username from all arrays
        .bind(payload.group_id)
        .execute(&mut *tx)
        .await;
    if let Err(e) = result {
        eprintln!("Failed to remove from previous clearance levels: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update clearance",
        )
            .into_response();
    }

    // Add to new clearance array
    let update_query = match payload.new_clearance.as_str() {
        "UNCLASSIFIED" => "UPDATE groups SET unclassified_clearance = array_append(unclassified_clearance, $1) WHERE id = $2",
        "CUI" => "UPDATE groups SET cui_clearance = array_append(cui_clearance, $1) WHERE id = $2",
        "SECRET" => "UPDATE groups SET secret_clearance = array_append(secret_clearance, $1) WHERE id = $2",
        "TOPSECRET" => "UPDATE groups SET topsecret_clearance = array_append(topsecret_clearance, $1) WHERE id = $2",
        _ => return (StatusCode::BAD_REQUEST, "Invalid clearance level").into_response(),
    };

    let result = sqlx::query(update_query)
        .bind(&payload.username) // Add username to new clearance array
        .bind(payload.group_id)
        .execute(&mut *tx)
        .await;

    match result {
        Ok(_) => {
            // Commit the transaction
            if let Err(e) = tx.commit().await {
                eprintln!("Failed to commit transaction: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to update clearance",
                )
                    .into_response();
            }
            (StatusCode::OK, "Clearance updated successfully").into_response()
        }
        Err(e) => {
            eprintln!("Database update error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to update clearance",
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct AddUserToGroupRequest {
    username: String,
    group_id: i32,
}

#[axum::debug_handler]
async fn add_user_to_group_handler(
    Extension(claims): Extension<Claims>,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<AddUserToGroupRequest>,
) -> impl IntoResponse {
    // Check if the requesting user is an admin of the group
    let is_admin = sqlx::query(
        "SELECT EXISTS (
            SELECT 1 FROM groups 
            WHERE id = $1 AND $2 = ANY(admins)
        )",
    )
    .bind(payload.group_id)
    .bind(&claims.sub) // Using username from claims
    .fetch_one(&pool)
    .await;

    match is_admin {
        Ok(row) => {
            let exists: bool = row.get::<bool, _>("exists");
            if !exists {
                return (
                    StatusCode::FORBIDDEN,
                    "Not authorized to add users to this group",
                )
                    .into_response();
            }
        }
        Err(e) => {
            eprintln!("Database error checking admin status: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    // Start a transaction
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Failed to start transaction: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    // Add the user to the group's group_ids array
    let result = sqlx::query(
        "UPDATE users 
         SET group_ids = array_append(group_ids, $1) 
         WHERE username = $2 
         AND NOT ($1 = ANY(group_ids))", // Prevent duplicate group_ids
    )
    .bind(payload.group_id)
    .bind(&payload.username)
    .execute(&mut *tx)
    .await;

    if let Err(e) = result {
        eprintln!("Database error updating user's group_ids: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to add user to group",
        )
            .into_response();
    }

    // Add the user to the unclassified clearance array by default
    let result = sqlx::query(
        "UPDATE groups 
         SET unclassified_clearance = array_append(unclassified_clearance, $1) 
         WHERE id = $2 
         AND NOT ($1 = ANY(unclassified_clearance))", // Prevent duplicate entries
    )
    .bind(&payload.username)
    .bind(payload.group_id)
    .execute(&mut *tx)
    .await;

    match result {
        Ok(_) => {
            // Commit the transaction
            if let Err(e) = tx.commit().await {
                eprintln!("Failed to commit transaction: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to add user to group",
                )
                    .into_response();
            }
            (StatusCode::OK, "User added to group successfully").into_response()
        }
        Err(e) => {
            eprintln!(
                "Database error adding user to unclassified clearance: {}",
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to add user to group",
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct UpdateAdminRequest {
    username: String,
    group_id: i32,
}

#[axum::debug_handler]
async fn promote_to_admin_handler(
    Extension(claims): Extension<Claims>,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<UpdateAdminRequest>,
) -> impl IntoResponse {
    // First check if the requesting user is already an admin of the group
    let is_admin = sqlx::query(
        "SELECT EXISTS (
            SELECT 1 FROM groups 
            WHERE id = $1 AND $2 = ANY(admins)
        )",
    )
    .bind(payload.group_id)
    .bind(&claims.sub) // Using username from claims
    .fetch_one(&pool)
    .await;

    match is_admin {
        Ok(row) => {
            let exists: bool = row.get::<bool, _>("exists");
            if !exists {
                return (
                    StatusCode::FORBIDDEN,
                    "Not authorized to modify admin status",
                )
                    .into_response();
            }
        }
        Err(e) => {
            eprintln!("Database error checking admin status: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    // Check if user is already an admin
    let already_admin = sqlx::query(
        "SELECT EXISTS (
            SELECT 1 FROM groups 
            WHERE id = $1 AND $2 = ANY(admins)
        )",
    )
    .bind(payload.group_id)
    .bind(&payload.username) // Using username from request
    .fetch_one(&pool)
    .await;

    match already_admin {
        Ok(row) => {
            let exists: bool = row.get::<bool, _>("exists");
            if exists {
                return (StatusCode::BAD_REQUEST, "User is already an admin").into_response();
            }
        }
        Err(e) => {
            eprintln!("Database error checking existing admin status: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    // Check if user is a member of the group
    let is_member = sqlx::query(
        "SELECT EXISTS (
            SELECT 1 FROM users 
            WHERE username = $1 
            AND $2 = ANY(group_ids)
        )",
    )
    .bind(&payload.username)
    .bind(payload.group_id)
    .fetch_one(&pool)
    .await;

    match is_member {
        Ok(row) => {
            let exists: bool = row.get::<bool, _>("exists");
            if !exists {
                return (
                    StatusCode::BAD_REQUEST,
                    "User must be a member of the group to become an admin",
                )
                    .into_response();
            }
        }
        Err(e) => {
            eprintln!("Database error checking group membership: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    // Add the user to the admins array
    let result = sqlx::query(
        "UPDATE groups 
         SET admins = array_append(admins, $1) 
         WHERE id = $2",
    )
    .bind(&payload.username) // Using username
    .bind(payload.group_id)
    .execute(&pool)
    .await;

    match result {
        Ok(_) => (StatusCode::OK, "User promoted to admin successfully").into_response(),
        Err(e) => {
            eprintln!("Database update error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to promote user to admin",
            )
                .into_response()
        }
    }
}

// Modified group creation to set creator as admin
#[derive(Deserialize)]
struct CreateGroupRequest {
    group_name: String,
    password: String,
    tags: Vec<String>,
}

#[axum::debug_handler]
async fn create_group_handler(
    Extension(claims): Extension<Claims>,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64("test").unwrap();
    // let salt = SaltString::generate(&mut OsRng);
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            eprintln!("Password hashing failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    // Randomly generate AES key (AES-256 key is 64 bytes) as vec of u8s
    let aes_key = rand::rng().random_range(0..u64::MAX).to_le_bytes();

    // Create group and set creator as admin
    let result: Result<sqlx::postgres::PgQueryResult, sqlx::Error> = sqlx::query(
        "INSERT INTO groups (group_name, password_hash, aes_key, tags, admins) 
         VALUES ($1, $2, $3, $4, ARRAY[$5])",
    )
    .bind(payload.group_name)
    .bind(password_hash)
    .bind(aes_key)
    .bind(payload.tags)
    .bind(claims.sub) // Add creator as first admin
    .execute(&pool)
    .await;

    match result {
        Ok(_) => (StatusCode::CREATED, "Group created successfully").into_response(),
        Err(e) => {
            eprintln!("Database insertion error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create group").into_response()
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize Ollama client pointing to the container.
    let ollama = Ollama::new("http://ollama".to_string(), 11434);
    let shared_state = Arc::new(AppState { ollama });

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool");

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_credentials(true)
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
            axum::http::header::CONTENT_TYPE,
        ]);

    // Apply JWT middleware only to the protected routes.
    let protected_routes = Router::new()
        .route("/query", post(query_handler))
        .route("/users/clearance", put(update_user_clearance_handler))
        .route("/groups/users", post(add_user_to_group_handler))
        .route("/groups/admins", post(promote_to_admin_handler))
        .route("/groups", post(create_group_handler))
        .layer(middleware::from_fn(jwt_auth_middleware));

    // Build the main router.
    let app = Router::new()
        .merge(protected_routes)
        .route("/health", get(health_handler))
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .layer(Extension(pool))
        .with_state(shared_state)
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind port 3000");

    println!("Server running on http://localhost:3000");
    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}
