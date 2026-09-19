use cindy::builtin::{Return, systemd};

// `impl Into<String>` lets callers pass a &str; one body generates the
// concrete #[remote] entry point and the ergonomic call-site shim.
#[cindy::action]
pub async fn restart(name: impl Into<String>) -> cindy::Result<Return> {
    systemd::restart(name).await
}

// Call it with a plain string literal:
async fn demo() -> cindy::Result<()> {
    restart("nginx").await?;
    Ok(())
}
