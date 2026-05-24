#[cindy::wire]
struct Vars {
    var_a: String,
    var_b: i64,
}

#[cindy::inventory]
fn inventory() -> cindy::Inventory<Vars> {
    cindy::Inventory::new([cindy::Host::new(
        "host.example.net",
        ["proxy", "prague"],
        Vars {
            var_a: "Hello, World!".into(),
            var_b: 42,
        },
    )])
}

#[cindy::remote]
fn do_work(a: String, b: i64) -> String {
    format!("The remote host created this string! ({a}, {b})")
}

#[cindy::main]
async fn main(host: cindy::Host<Vars>) -> cindy::Result<()> {
    let result = do_work(host.vars.var_a, host.vars.var_b).await;
    println!("{result}");

    Ok(())
}
