use dioxus::prelude::*;

mod docs;
mod sections;

use docs::Docs;
use sections::{Cta, Demo, Example, Features, Footer, Hero, Nav};

fn main() {
    dioxus::launch(App);
}

/// Site routes. `Home` is the single-scroll landing; `Docs` is the long-form
/// Getting Started / reference page.
#[derive(Clone, Routable, PartialEq)]
enum Route {
    #[route("/")]
    Home {},
    #[route("/docs")]
    Docs {},
}

#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: asset!("/assets/favicon.png") }
        document::Link { rel: "stylesheet", href: asset!("/assets/tailwind.css") }
        document::Link { rel: "preconnect", href: "https://fonts.googleapis.com" }
        document::Link {
            rel: "preconnect",
            href: "https://fonts.gstatic.com",
            crossorigin: "anonymous",
        }

        // asciinema-player (plays the .cast recording in the Demo section).
        document::Link {
            rel: "stylesheet",
            href: "https://cdn.jsdelivr.net/npm/asciinema-player@3.16.0/dist/bundle/asciinema-player.min.css",
        }
        document::Script {
            src: "https://cdn.jsdelivr.net/npm/asciinema-player@3.16.0/dist/bundle/asciinema-player.min.js",
        }

        Router::<Route> {}
    }
}

/// The landing page (everything that used to live directly in `App`).
#[component]
fn Home() -> Element {
    rsx! {
        div { class: "min-h-screen flex flex-col",
            Nav {}
            main { class: "flex-1",
                Hero {}
                Example {}
                Demo {}
                Features {}
                Cta {}
            }
            Footer {}
        }
    }
}
