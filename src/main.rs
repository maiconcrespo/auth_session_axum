use anyhow::Ok;
use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{Next, from_fn},
    response::IntoResponse,
    routing::{get, post},
};
use axum_session::{Key, SessionConfig, SessionLayer, SessionStore};
use axum_session_auth::{AuthConfig, AuthSession, AuthSessionLayer, Authentication};
use axum_session_sqlx::SessionSqlitePool;
use serde::Deserialize;
use sqlx::{Executor, Pool, Sqlite, SqlitePool, prelude::FromRow};

#[tokio::main]
/// Main entry point of the application
/// Sets up the database, session store, and starts the web server on port 3000
async fn main() {
    println!("Starting application...");

    println!("Initializing database...");
    let pool = db().await;
    println!("Database initialized successfully");

    println!("Setting up session store...");
    let session_store = session(pool.clone()).await;
    println!("Session store configured successfully");

    println!("Building application router...");
    let app = app(pool, session_store);
    println!("Application router built successfully");

    println!("Binding to TCP listener on 0.0.0.0:3000...");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server listening on 0.0.0.0:3000");

    println!("Starting web server...");
    axum::serve(listener, app).await.unwrap();
}

/// Initializes the SQLite database connection and creates the user table
/// Creates a default guest user if no user with id=1 exists
/// Returns the database connection pool
async fn db() -> Pool<Sqlite> {
    println!("Connecting to SQLite database...");
    let pool = sqlx::sqlite::SqlitePool::connect("sqlite://db.sqlite")
        .await
        .unwrap();
    println!("Connected to SQLite database successfully");

    println!("Creating user table if not exists...");
    pool.execute(
        "
        CREATE TABLE IF NOT EXISTS user(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
        ",
    )
    .await
    .unwrap();
    println!("User table created/verified successfully");

    println!("Checking for existing guest user (id=1)...");
    let rows: Vec<UserSql> = sqlx::query_as("SELECT * FROM user WHERE id = ?1")
        .bind(&1)
        .fetch_all(&pool)
        .await
        .unwrap();

    if rows.len() == 0 {
        println!("No guest user found, creating default guest user...");
        sqlx::query("INSERT INTO user (username, password) VALUES (?1,?2)")
            .bind(&"guest")
            .bind(&"guest")
            .execute(&pool)
            .await
            .unwrap();
        println!("Default guest user created successfully");
    } else {
        println!("Guest user already exists");
    }

    println!("Database setup completed");
    pool
}

/// Creates and configures the session store for managing user sessions
/// Uses SQLite as the session backend with a custom table name
/// Returns the configured session store
async fn session(pool: Pool<Sqlite>) -> SessionStore<SessionSqlitePool> {
    println!("Creating session configuration...");
    let config = SessionConfig::default()
        .with_table_name("session_table")
        .with_key(Key::generate());
    println!("Session configuration created");

    println!("Initializing session store...");
    let session_store = SessionStore::<SessionSqlitePool>::new(Some(pool.clone().into()), config)
        .await
        .unwrap();
    println!("Session store initialized successfully");

    session_store
}

/// Constructs the Axum router with all routes and middleware layers
/// Sets up authentication, session management, and routing for the web application
/// Returns the configured router
fn app(pool: Pool<Sqlite>, session_store: SessionStore<SessionSqlitePool>) -> Router {
    println!("Creating authentication configuration...");
    let config = AuthConfig::<i64>::default().with_anonymous_user_id(Some(1));
    println!("Authentication configuration created");

    println!("Building router with routes and middleware...");
    Router::new()
        .route("/", get(|| async { "Hello World!" }))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", get(log_out))
        .route("/protected", get(protected).route_layer(from_fn(auth)))
        .layer(
            AuthSessionLayer::<User, i64, SessionSqlitePool, SqlitePool>::new(Some(pool.clone()))
                .with_config(config),
        )
        .layer(SessionLayer::new(session_store))
        .with_state(pool)
}

/// Handles user registration requests
/// Checks if username already exists, hashes the password, and creates a new user
/// Returns success or error response based on registration outcome
async fn register(
    State(pool): State<Pool<Sqlite>>,
    Json(user): Json<UserRequest>,
) -> impl IntoResponse {
    println!("Registration attempt for username: {}", user.username);

    println!("Checking if username already exists...");
    let rows: Vec<UserSql> = sqlx::query_as("SELECT * FROM user WHERE username = ?1")
        .bind(&user.username)
        .fetch_all(&pool)
        .await
        .unwrap();

    if rows.len() != 0 {
        println!(
            "Registration failed: Username '{}' already exists",
            user.username
        );
        let msg = format!("Username:{} is already taken", user.username);
        (StatusCode::BAD_REQUEST, msg).into_response()
    } else {
        println!("Username available, hashing password...");
        let hash_password = bcrypt::hash(user.password, 10).unwrap();
        println!("Password hashed successfully");

        println!("Inserting new user into database...");
        sqlx::query("INSERT INTO user (username,password) VALUES (?1,?2)")
            .bind(&user.username)
            .bind(&hash_password)
            .execute(&pool)
            .await
            .unwrap();
        println!("User '{}' registered successfully", user.username);
        (StatusCode::OK, "Register sucssesfull!").into_response()
    }
}

/// Handles user login requests
/// Verifies username and password, creates authenticated session if valid
/// Returns success or error response based on login attempt
async fn login(
    auth: AuthSession<User, i64, SessionSqlitePool, SqlitePool>,
    State(pool): State<Pool<Sqlite>>,
    Json(user): Json<UserRequest>,
) -> impl IntoResponse {
    println!("Login attempt for username: {}", user.username);

    println!("Looking up user in database...");
    let rows: Vec<UserSql> = sqlx::query_as("SELECT * FROM user WHERE username = ?1")
        .bind(&user.username)
        .fetch_all(&pool)
        .await
        .unwrap();

    if rows.len() == 0 {
        println!("Login failed: Username '{}' not found", user.username);
        let msg = format!("Username:{} is not found", user.username);
        return (StatusCode::BAD_REQUEST, msg).into_response();
    } else {
        println!("User found, verifying password...");
        let is_valid = bcrypt::verify(user.password, &rows[0].password).unwrap();

        if is_valid {
            println!("Password valid, logging in user with ID: {}", rows[0].id);
            auth.login_user(rows[0].id as i64);
            println!("User '{}' logged in successfully", user.username);
            (StatusCode::OK, "Login successfull").into_response()
        } else {
            println!(
                "Login failed: Invalid password for user '{}'",
                user.username
            );
            (StatusCode::BAD_REQUEST, "Invalid password").into_response()
        }
    }
}

/// Handles user logout requests
/// Terminates the current user session
/// Returns success response confirming logout
async fn log_out(auth: AuthSession<User, i64, SessionSqlitePool, SqlitePool>) -> impl IntoResponse {
    println!("Logout request received");
    auth.logout_user();
    println!("User logged out successfully");
    (StatusCode::OK, "Logout successfull").into_response()
}

/// Protected route handler that requires authentication
/// Displays a personalized message with user information
/// Only accessible to authenticated users
async fn protected(Extension(user): Extension<User>) -> impl IntoResponse {
    println!(
        "Protected route accessed by user: {} (ID: {})",
        user.username, user.id
    );
    let msg = format!("Hello,{}, your id is {}", user.username, user.id);
    (StatusCode::OK, msg).into_response()
}

/// Authentication middleware that protects routes
/// Checks if user is authenticated and adds user data to request extensions
/// Returns unauthorized response for unauthenticated requests
async fn auth(
    auth: AuthSession<User, i64, SessionSqlitePool, SqlitePool>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    println!("Authentication middleware called");

    if auth.is_authenticated() {
        let user = auth.current_user.unwrap().clone();
        println!("User authenticated: {} (ID: {})", user.username, user.id);
        req.extensions_mut().insert(user);
        next.run(req).await
    } else {
        println!("Authentication failed: User not authenticated");
        (StatusCode::UNAUTHORIZED, "Guest, you areUnauthorized").into_response()
    }
}

#[derive(Deserialize)]
struct UserRequest {
    username: String,
    password: String,
}

#[derive(Clone)]
pub struct User {
    pub id: i64,
    pub anonymous: bool,
    pub username: String,
}
#[async_trait]
impl Authentication<User, i64, SqlitePool> for User {
    /// Loads a user from the database by user ID
    /// Returns guest user for ID 1, otherwise fetches user from database
    async fn load_user(userid: i64, pool: Option<&SqlitePool>) -> Result<User, anyhow::Error> {
        println!("Loading user with ID: {}", userid);

        if userid == 1 {
            println!("Loading anonymous guest user");
            Ok(User {
                id: userid,
                anonymous: true,
                username: "guest".to_string(),
            })
        } else {
            println!("Loading authenticated user from database...");
            let user: UserSql = sqlx::query_as("SELECT * FROM user WHERE id =?1")
                .bind(userid)
                .fetch_one(pool.unwrap())
                .await?;

            println!("User loaded: {} (ID: {})", user.username, user.id);
            Ok(User {
                id: user.id as i64,
                anonymous: false,
                username: user.username,
            })
        }
    }

    /// Checks if the user is authenticated (not anonymous)
    fn is_authenticated(&self) -> bool {
        !self.anonymous
    }

    /// Checks if the user account is active (not anonymous)
    fn is_active(&self) -> bool {
        !self.anonymous
    }

    /// Checks if the user is anonymous (guest user)
    fn is_anonymous(&self) -> bool {
        self.anonymous
    }
}

#[derive(FromRow)]
struct UserSql {
    id: i64,
    username: String,
    password: String,
}
