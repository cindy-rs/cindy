#[cindy::remote]
fn read_kernel() -> cindy::Result<String> {
    // Runs ON THE HOST.
    Ok(std::fs::read_to_string("/proc/version")?)
}

#[cindy::main]
async fn main(_host: cindy::Host) -> cindy::Result<()> {
    // Runs on YOUR machine; the call hops to the host and back.
    let kernel = read_kernel().await?;
    println!("remote kernel: {kernel}");
    Ok(())
}
