use async_trait::async_trait;
use axum::{
    Router,
    routing::{get, post},
};
use axum_session::{Key, SessionConfig, SessionStore};
use axum_session_auth::{AuthConfig, AuthSessionLayer, Authentication};
use axum_session_sqlx::SessionSqlitePool;
use sqlx::{Executor, Pool, Sqlite, SqlitePool, prelude::FromRow};

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

fn app(pool: Pool<Sqlite>, session_store: SessionStore<SessionSqlitePool>) -> Router {
    let config = AuthConfig::<i64>::default().with_anonymous_user_id(Some(1));
    Router::new()
        .route("/", get(|| async { "Hello World!" }))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", get(logout))
        .route("/protected", get(protected).route_layer(from_fn(auth)))
        .layer(
            AuthSessionLayer::<User, i64, SessionSqlitePool, SqlitePool>::new(Some(pool.clone()))
                .with_config(config),
        )
        .layer(SessionLayer::new(session_store))
        .with_state(pool)
}

#[derive(Clone)]
pub struct User {
    pub id: i64,
    pub anonymous: bool,
    pub username: String,
}
#[async_trait]
impl Authentication<User, i64, SqlitePool> for User {
    #[must_use]
    #[allow(
        elided_named_lifetimes,
        clippy::type_complexity,
        clippy::type_repetition_in_bounds
    )]
    async fn load_user(userid: i64, pool: Option<&SqlitePool>) -> Result<User, anyhow::Error> {
        todo!()
    }

    fn is_authenticated(&self) -> bool {
        todo!()
    }

    fn is_active(&self) -> bool {
        todo!()
    }

    fn is_anonymous(&self) -> bool {
        todo!()
    }
}

#[derive(FromRow)]
struct UserSql {
    id: i32,
    username: String,
    password: String,
}
