#[cindy::wire]
enum Vars {
    Nginx {
        nginx_package: String,
        nginx_version: String,
        nginx_config: String,
    },
}

const NGINX_CONFIG: &str = "\
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    server {
        listen 80;
        server_name example.com;
        root /var/www/html;
        index index.html;
    }
}
";

#[cindy::inventory]
fn inventory() -> cindy::Inventory<Vars> {
    cindy::Inventory::new([cindy::Host::new(
        "host.example.net",
        ["location:prague", "service:nginx"],
        Vars::Nginx {
            nginx_package: "nginx-full".into(),
            nginx_version: "1.22.1-9+deb12u8".into(),
            nginx_config: NGINX_CONFIG.into(),
        },
    )])
}

#[cindy::main]
async fn main(host: cindy::Host<Vars>) -> cindy::Result<()> {
    use cindy::builtin::{debian::apt, path, systemd};

    match host.vars {
        Vars::Nginx {
            nginx_package,
            nginx_version,
            nginx_config,
        } => {
            let install = apt::hold(nginx_package, nginx_version).await?;

            let copy_config = path::file(
                "/etc/nginx/nginx.conf",
                nginx_config,
                "root",
                "root",
                cindy::mode!(0o644),
            )
            .await?;

            systemd::enable_and_start("nginx").await?;

            if install.changed() || copy_config.changed() {
                systemd::restart("nginx").await?;
            }
        }
    };

    Ok(())
}
