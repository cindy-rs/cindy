// `impl Into<String>` lets callers pass a &str; one body generates the
// concrete #[remote] entry point and the ergonomic call-site shim.
#[cindy::action]
pub async fn restart(name: impl Into<String>) -> cindy::Result<Return> {
    apply(State {
        name: name.into(),
        enablement: None,
        runtime: Some(RuntimeAction::Restarted),
    })
    .await
}

// Call it with a plain string literal:
restart("nginx").await?;
