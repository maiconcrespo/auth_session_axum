use axum::{
    Router,
    routing::{get, post},
};
use axum_session::{Key, SessionConfig, SessionStore};
use axum_session_auth::AuthSessionLayer;
use axum_session_sqlx::SessionSqlitePool;
use sqlx::{Executor, Pool, Sqlite, prelude::FromRow};

#[tokio::main]

async fn main() {
    println!("Hello, world!");
}

async fn db() -> Pool<Sqlite> {
    let pool = sqlx::sqlite::SqlitePool::connect("sqlite://db.sqlite")
        .await
        .unwrap();

    pool.execute(
        "
        CREATE TABLE IF NO EXISTS user(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
        ",
    )
    .await
    .unwrap();

    let rows: Vec<UserSql> = sqlx::query_as("SELECT * FROM user WHERE id = ?1")
        .bind(&1)
        .fetch_all(&pool)
        .await
        .unwrap();

    if rows.len() == 0 {
        sqlx::query("INSERT INTO user (username, password) VALUES (?1,?2)")
            .bind(&"guest")
            .bind(&"guest")
            .execute(&pool)
            .await
            .unwrap();
    }
    pool
}

async fn session(pool: Pool<Sqlite>) -> SessionStore<SessionSqlitePool> {
    let config = Box::new(
        SessionConfig::default()
            .with_table_name("session_table")
            .with_key(Key::generate()),
    );
    let session_store = SessionStore::<SessionSqlitePool>::new(Some(pool.clone().into()), config)
        .await
        .unwrap();
    session_store
}

fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "Hello World!" }))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", get(logout))
        .route("/protected", get(protected).route_layer(from_fn(auth)))
        .layer(AuthSessionLayer::<User>::new(pool))
}

#[derive(Clone)]
pub struct User {
    pub id: i64,
    pub anonymous: bool,
    pub username: String,
}

#[derive(FromRow)]
struct UserSql {
    id: i32,
    username: String,
    password: String,
}
