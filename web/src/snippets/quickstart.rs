#[cindy::wire]
struct Vars {
    greeting: String,
}

#[cindy::inventory]
fn inventory() -> cindy::Inventory<Vars> {
    cindy::Inventory::new([cindy::Host::new(
        "host.example.net",
        ["proxy", "prague"],
        Vars { greeting: "Hello".into() },
    )])
}

#[cindy::remote]
fn greet(who: String) -> String {
    format!("{who} from the remote host!")
}

#[cindy::main]
async fn main(host: cindy::Host<Vars>) -> cindy::Result<()> {
    use cindy::builtin::{debian::apt, systemd};

    apt::install("nginx").await?;
    if apt::install("curl").await?.changed() {
        systemd::restart("nginx").await?;
    }

    println!("{}", greet(host.vars.greeting).await);
    Ok(())
}
