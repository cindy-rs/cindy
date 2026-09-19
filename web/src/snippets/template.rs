#[derive(askama::Template)]
#[template(
    source = "listen = {{ port }}\npassword = {{ password }}\n",
    ext = "txt"
)]
struct AppConf<'a> {
    password: &'a cindy::Secret<String>,
    port: u16,
}

#[cindy::remote]
async fn write_config(password: cindy::Secret<String>) -> cindy::Result<()> {
    // No `.reveal()`, no annotations: the secret goes into the template
    // and cindy takes care of the rest. The file on disk gets the real
    // password; the diff shows `password = ***` next to a fully visible
    // `listen = 8080`.
    cindy::builtin::path::template::inner(
        "/etc/app.conf",
        &AppConf {
            password: &password,
            port: 8080,
        },
        "root",
        "root",
        cindy::builtin::path::Mode::try_from(0o600)?,
    )?;
    Ok(())
}
