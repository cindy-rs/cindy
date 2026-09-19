// Sync body: runs on a blocking thread on the worker.
#[cindy::remote]
fn hostname() -> cindy::Result<String> {
    Ok(std::fs::read_to_string("/etc/hostname")?)
}

// Async body: awaited directly on the worker.
#[cindy::remote]
async fn fetch_url(url: String) -> cindy::Result<String> {
    // ... async I/O ...
    Ok(url)
}

// Either way, the orchestrator call is a future:
let name = hostname().await?;
