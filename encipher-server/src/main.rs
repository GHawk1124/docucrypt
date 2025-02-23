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
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::{fmt, EnvFilter};

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
    "deepseek-r1:1.5b".to_string()
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
        "SELECT username, password_hash FROM users WHERE username = $1",
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
    group_name: String,
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

    // Combined check for: requester is admin AND target is member of the SAME group
    let checks = sqlx::query(
        "WITH specific_group AS (
            SELECT group_name, admins 
            FROM groups 
            WHERE group_name = $1
        )
        SELECT 
            (SELECT $2 = ANY(admins) FROM specific_group) as is_requester_admin,
            (
                SELECT EXISTS (
                    SELECT 1 FROM users 
                    WHERE username = $3 
                    AND $1 = ANY(group_names)
                )
            ) as is_target_member
        FROM specific_group",
    )
    .bind(&payload.group_name)
    .bind(&claims.sub)
    .bind(&payload.username)
    .fetch_one(&pool)
    .await;

    match checks {
        Ok(row) => {
            let is_requester_admin: bool = row.get("is_requester_admin");
            let is_target_member: bool = row.get("is_target_member");

            if !is_requester_admin {
                return (
                    StatusCode::FORBIDDEN,
                    "Not authorized to update clearance level for this group",
                )
                    .into_response();
            }
            if !is_target_member {
                return (
                    StatusCode::BAD_REQUEST,
                    "Target user is not a member of this group",
                )
                    .into_response();
            }
        }
        Err(e) => {
            eprintln!("Database error checking permissions: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    // Start a transaction
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
    };

    // Remove from all clearance arrays first
    let remove_query = "
        UPDATE groups 
        SET 
            unclassified_clearance = array_remove(unclassified_clearance, $1),
            cui_clearance = array_remove(cui_clearance, $1),
            secret_clearance = array_remove(secret_clearance, $1),
            topsecret_clearance = array_remove(topsecret_clearance, $1)
        WHERE group_name = $2";

    let result = sqlx::query(remove_query)
        .bind(&payload.username)
        .bind(&payload.group_name)
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
        "UNCLASSIFIED" => "UPDATE groups SET unclassified_clearance = array_append(unclassified_clearance, $1) WHERE group_name = $2",
        "CUI" => "UPDATE groups SET cui_clearance = array_append(cui_clearance, $1) WHERE group_name = $2",
        "SECRET" => "UPDATE groups SET secret_clearance = array_append(secret_clearance, $1) WHERE group_name = $2",
        "TOPSECRET" => "UPDATE groups SET topsecret_clearance = array_append(topsecret_clearance, $1) WHERE group_name = $2",
        _ => return (StatusCode::BAD_REQUEST, "Invalid clearance level").into_response(),
    };
    let result = sqlx::query(update_query)
        .bind(&payload.username)
        .bind(&payload.group_name)
        .execute(&mut *tx)
        .await;

    match result {
        Ok(_) => {
            if let Err(_) = tx.commit().await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to update clearance",
                )
                    .into_response();
            }
            (StatusCode::OK, "Clearance updated successfully").into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update clearance",
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct AddUserToGroupRequest {
    username: String,
    group_name: String,
}

#[axum::debug_handler]
async fn admin_add_user_to_group_handler(
    Extension(claims): Extension<Claims>,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<AddUserToGroupRequest>,
) -> impl IntoResponse {
    // Combined check for: requester is admin, target is not already in group
    let checks = sqlx::query(
        "WITH specific_group AS (
            SELECT group_name, admins 
            FROM groups 
            WHERE group_name = $1
        )
        SELECT 
            (SELECT $2 = ANY(admins) FROM specific_group) as is_requester_admin,
            (
                SELECT NOT EXISTS (
                    SELECT 1 FROM users 
                    WHERE username = $3 
                    AND $1 = ANY(group_names)
                )
            ) as is_valid_target
        FROM specific_group",
    )
    .bind(&payload.group_name)
    .bind(&claims.sub)
    .bind(&payload.username)
    .fetch_one(&pool)
    .await;

    match checks {
        Ok(row) => {
            let is_requester_admin: bool = row.get("is_requester_admin");
            let is_valid_target: bool = row.get("is_valid_target");

            if !is_requester_admin {
                return (
                    StatusCode::FORBIDDEN,
                    "Not authorized to add users to this group",
                )
                    .into_response();
            }
            if !is_valid_target {
                return (
                    StatusCode::BAD_REQUEST,
                    "User is already a member of this group",
                )
                    .into_response();
            }
        }
        Err(e) => {
            eprintln!("Database error checking permissions: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
    };

    // Add user to group_names
    let result = sqlx::query(
        "UPDATE users 
         SET group_names = array_append(group_names, $1) 
         WHERE username = $2
         AND NOT ($1 = ANY(group_names))", // Prevent duplicate group_names
    )
    .bind(&payload.group_name)
    .bind(&payload.username)
    .execute(&mut *tx)
    .await;

    if let Err(_) = result {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to add user to group",
        )
            .into_response();
    }

    // Add user to unclassified_clearance
    let result = sqlx::query(
        "UPDATE groups 
         SET unclassified_clearance = array_append(unclassified_clearance, $1) 
         WHERE group_name = $2
         AND NOT ($1 = ANY(unclassified_clearance))", // Prevent duplicate entries
    )
    .bind(&payload.username)
    .bind(&payload.group_name)
    .execute(&mut *tx)
    .await;

    match result {
        Ok(_) => {
            if let Err(_) = tx.commit().await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to add user to group",
                )
                    .into_response();
            }
            (StatusCode::OK, "User added to group successfully").into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to add user to group",
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct JoinGroupRequest {
    group_name: String,
    password: String,
}

#[axum::debug_handler]
async fn user_join_group_handler(
    Extension(claims): Extension<Claims>,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<JoinGroupRequest>,
) -> impl IntoResponse {
    let group = match sqlx::query("SELECT password_hash FROM groups WHERE group_name = $1")
        .bind(&payload.group_name)
        .fetch_one(&pool)
        .await
    {
        Ok(row) => row,
        Err(_) => return (StatusCode::NOT_FOUND, "Group not found").into_response(),
    };

    let password_hash_db: String = group.get("password_hash");
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64("dGVzdHRlc3R0ZXN0dGVzdA").unwrap();
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            eprintln!("Password hashing failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    if password_hash_db != password_hash {
        return (StatusCode::UNAUTHORIZED, "Invalid password").into_response();
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response(),
    };

    // Add user to group_names
    let result = sqlx::query(
        "UPDATE users 
         SET group_names = array_append(group_names, $1) 
         WHERE username = $2 
         AND NOT ($1 = ANY(group_names))
         AND NOT EXISTS (
         SELECT 1 FROM groups 
         WHERE group_name = $1 
         AND $2 = ANY(admins)
     )",
    )
    .bind(&payload.group_name)
    .bind(&claims.sub)
    .execute(&mut *tx)
    .await;

    if let Err(_) = result {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to join group").into_response();
    }

    // Add user to unclassified_clearance
    let result = sqlx::query(
        "UPDATE groups 
         SET unclassified_clearance = array_append(unclassified_clearance, $1) 
         WHERE group_name = $2 
         AND NOT ($1 = ANY(unclassified_clearance))",
    )
    .bind(&claims.sub)
    .bind(&payload.group_name)
    .execute(&mut *tx)
    .await;

    match result {
        Ok(_) => {
            if let Err(_) = tx.commit().await {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to join group").into_response();
            }
            (StatusCode::OK, "Successfully joined group").into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to join group").into_response(),
    }
}

#[derive(Deserialize)]
struct UpdateAdminRequest {
    username: String,
    group_name: String,
}

#[axum::debug_handler]
async fn promote_to_admin_handler(
    Extension(claims): Extension<Claims>,
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<UpdateAdminRequest>,
) -> impl IntoResponse {
    // Combined check for: requester is admin, target is member but not admin
    let checks = sqlx::query(
        "WITH specific_group AS (
            SELECT group_name, admins 
            FROM groups 
            WHERE group_name = $1
        )
        SELECT 
            (SELECT $2 = ANY(admins) FROM specific_group) as is_requester_admin,
            (
                SELECT EXISTS (
                    SELECT 1 FROM users 
                    WHERE username = $3 
                    AND $1 = ANY(group_names)
                    AND NOT EXISTS (
                        SELECT 1 FROM groups 
                        WHERE group_name = $1 
                        AND $3 = ANY(admins)
                    )
                )
            ) as is_valid_target
        FROM specific_group",
    )
    .bind(&payload.group_name)
    .bind(&claims.sub)
    .bind(&payload.username)
    .fetch_one(&pool)
    .await;

    match checks {
        Ok(row) => {
            let is_requester_admin: bool = row.get("is_requester_admin");
            let is_valid_target: bool = row.get("is_valid_target");

            if !is_requester_admin {
                return (
                    StatusCode::FORBIDDEN,
                    "Not authorized to modify admin status",
                )
                    .into_response();
            }
            if !is_valid_target {
                return (
                    StatusCode::BAD_REQUEST,
                    "Target user is either not a member or already an admin",
                )
                    .into_response();
            }
        }
        Err(e) => {
            eprintln!("Database error checking permissions: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    }

    // Promote to admin and update clearances
    let result = sqlx::query(
        "UPDATE groups 
         SET admins = array_append(admins, $1),
             topsecret_clearance = array_append(topsecret_clearance, $1),
             unclassified_clearance = array_remove(unclassified_clearance, $1),
             cui_clearance = array_remove(cui_clearance, $1),
             secret_clearance = array_remove(secret_clearance, $1)
         WHERE group_name = $2",
    )
    .bind(&payload.username)
    .bind(&payload.group_name)
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
    let salt = SaltString::from_b64("dGVzdHRlc3R0ZXN0dGVzdA").unwrap();
    // let salt = SaltString::generate(&mut OsRng);
    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            eprintln!("Password hashing failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Failed to start transaction: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    // Randomly generate AES key (AES-256 key is 64 bytes) as vec of u8s
    let aes_key = rand::rng().random_range(0..u64::MAX).to_le_bytes();

    // Create group and set creator as admin
    let result: Result<sqlx::postgres::PgQueryResult, sqlx::Error> = sqlx::query(
        "INSERT INTO groups (group_name, password_hash, aes_key, tags, admins, topsecret_clearance) 
         VALUES ($1, $2, $3, $4, ARRAY[$5], ARRAY[$5])",
    )
    .bind(payload.group_name.clone())
    .bind(password_hash)
    .bind(aes_key)
    .bind(payload.tags)
    .bind(claims.sub.clone()) // Add creator as first admin
    .execute(&mut *tx)
    .await;

    if let Err(e) = result {
        eprintln!("Database insertion error: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create group").into_response();
    }

    // Add group to creator's group_names
    let result = sqlx::query(
        "UPDATE users 
         SET group_names = array_append(group_names, $1) 
         WHERE username = $2",
    )
    .bind(payload.group_name.clone())
    .bind(claims.sub.clone())
    .execute(&mut *tx)
    .await;

    match result {
        Ok(_) => {
            if let Err(e) = tx.commit().await {
                eprintln!("Failed to commit transaction: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create group")
                    .into_response();
            }
            (StatusCode::CREATED, "Group created successfully").into_response()
        }
        Err(e) => {
            eprintln!("Database update error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create group").into_response()
        }
    }
}

#[derive(Serialize)]
struct GroupInfo {
    group_name: String,
    clearance: String,
    is_admin: bool,
}

#[derive(Serialize)]
struct UserInfoResponse {
    username: String,
    groups: Vec<GroupInfo>,
}

#[axum::debug_handler]
async fn get_user_info_handler(
    Extension(claims): Extension<Claims>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<UserInfoResponse>, (StatusCode, String)> {
    let groups = sqlx::query(
        "SELECT 
            g.group_name,
            CASE 
                WHEN $1 = ANY(g.topsecret_clearance) THEN 'TOPSECRET'
                WHEN $1 = ANY(g.secret_clearance) THEN 'SECRET'
                WHEN $1 = ANY(g.cui_clearance) THEN 'CUI'
                WHEN $1 = ANY(g.unclassified_clearance) THEN 'UNCLASSIFIED'
            END as clearance,
            $1 = ANY(g.admins) as is_admin
        FROM groups g
        WHERE $1 = ANY(g.unclassified_clearance) 
           OR $1 = ANY(g.cui_clearance)
           OR $1 = ANY(g.secret_clearance)
           OR $1 = ANY(g.topsecret_clearance)",
    )
    .bind(&claims.sub)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        eprintln!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to fetch user info".to_string(),
        )
    })?;

    let groups_info: Vec<GroupInfo> = groups
        .into_iter()
        .map(|row| GroupInfo {
            group_name: row.get("group_name"),
            clearance: row.get("clearance"),
            is_admin: row.get("is_admin"),
        })
        .collect();

    Ok(Json(UserInfoResponse {
        username: claims.sub,
        groups: groups_info,
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

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
        .route("/groups/users/add", post(admin_add_user_to_group_handler))
        .route("/groups/users/join", post(user_join_group_handler))
        .route("/groups/admins/promote", post(promote_to_admin_handler))
        .route("/groups", post(create_group_handler))
        .route("/users/info", get(get_user_info_handler))
        .layer(middleware::from_fn(jwt_auth_middleware));

    // Build the main router.
    let app = Router::new()
        .merge(protected_routes)
        .route("/health", get(health_handler))
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .layer(Extension(pool))
        .with_state(shared_state)
        .layer(cors)
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_request(tower_http::trace::DefaultOnRequest::new().level(Level::INFO)),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind port 3000");

    println!("Server running on http://localhost:3000");
    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}
