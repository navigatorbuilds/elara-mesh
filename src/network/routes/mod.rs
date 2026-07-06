//! Route modules — split from server.rs for maintainability.
//!
//! Each module contains axum handler functions grouped by domain.
//! The router composition lives in `super::server::routes()`.

pub mod admin;
pub mod core;
pub mod explorer;
pub mod sync;
pub mod token;
pub mod transitions;
