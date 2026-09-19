use dioxus::prelude::*;

use crate::Route;

const REPO: &str = "https://github.com/cindy-rs/cindy";
const DISCORD: &str = "https://discord.gg/M7x6hyq57h";

/// The full, detailed logo art (PNG). Used as the hero centerpiece.
#[component]
pub fn Logo(class: String) -> Element {
    rsx! {
        img {
            src: asset!("/assets/logo.png"),
            alt: "Cindy Logo",
            class: "mx-auto max-w-3xs drop-shadow-[0_0_40px_rgba(249,115,22,0.15)] sm:max-w-12",
        }
    }
}

/// A small ember-spark mark rendered as inline SVG — crisp at any size,
/// no asset round-trip. Used for the nav and footer wordmark glyph where
/// the detailed PNG would look muddy.
#[component]
pub fn Spark(class: String) -> Element {
    rsx! {
        svg {
            class,
            view_box: "0 0 24 24",
            fill: "none",
            xmlns: "http://www.w3.org/2000/svg",
            path {
                d: "M12 2c.8 3.2-1.4 4.8-2.8 6.4C7.6 10.2 7 11.8 7 13.6 7 17.1 9.9 20 13.4 20c3.1 0 5.6-2.3 5.6-5.4 0-2.6-1.4-4.3-2.7-5.8-1-1.1-1.9-2.2-1.8-3.6-1.2.7-2 1.8-2.4 3.1C11.3 6.7 11.6 4.2 12 2z",
                fill: "url(#ember)",
            }
            defs {
                linearGradient {
                    id: "ember",
                    x1: "7",
                    y1: "2",
                    x2: "19",
                    y2: "20",
                    gradient_units: "userSpaceOnUse",
                    stop { offset: "0", stop_color: "#fdba74" }
                    stop { offset: "1", stop_color: "#ea580c" }
                }
            }
        }
    }
}

#[component]
pub fn Nav() -> Element {
    rsx! {
        header { class: "sticky top-0 z-50 border-b border-line/60 bg-ink/80 backdrop-blur-md",
            nav { class: "mx-auto flex h-16 max-w-6xl items-center justify-between px-5 sm:px-8",
                Link {
                    to: Route::Home {},
                    class: "flex items-center gap-2.5",
                    Spark { class: "h-6 w-6" }
                    span { class: "text-lg font-bold tracking-tight", "Cindy" }
                }
                div { class: "hidden items-center gap-8 text-sm font-medium text-zinc-400 sm:flex",
                    a { href: "#example", class: "transition-colors hover:text-white", "Example" }
                    a { href: "#features", class: "transition-colors hover:text-white", "Why Cindy" }
                    Link {
                        to: Route::Docs {},
                        class: "transition-colors hover:text-white",
                        "Docs"
                    }
                    a {
                        href: REPO,
                        class: "transition-colors hover:text-white",
                        "Source"
                    }
                    a {
                        href: DISCORD,
                        class: "transition-colors hover:text-white",
                        "Discord"
                    }
                }
                Link {
                    to: Route::Docs {},
                    class: "rounded-lg bg-white px-4 py-1.5 text-sm font-semibold text-ink transition-transform hover:scale-[1.03] active:scale-95",
                    "Get started"
                }
            }
        }
    }
}

#[component]
pub fn Hero() -> Element {
    rsx! {
        section {
            id: "top",
            class: "relative overflow-hidden border-b border-line/60",
            div { class: "pointer-events-none absolute inset-0 bg-grid opacity-40" }
            div { class: "pointer-events-none absolute inset-0 bg-ember-glow" }

            div { class: "relative mx-auto max-w-6xl px-5 pb-24 pt-20 text-center sm:px-8 sm:pt-28",
                img {
                    src: asset!("/assets/logo.png"),
                    alt: "Cindy — half human, half machine",
                    class: "mx-auto mt-10 w-full max-w-md drop-shadow-[0_0_40px_rgba(249,115,22,0.15)] sm:max-w-lg",
                }

                h1 { class: "mx-auto mt-10 max-w-4xl text-balance text-5xl font-extrabold leading-[1.05] tracking-tight sm:text-7xl",
                    "Managing infrastructure at "
                    span { class: "text-gradient", "breakneck speed" }
                    "."
                }

                p { class: "mx-auto mt-6 max-w-2xl text-pretty text-lg text-zinc-400 sm:text-xl",
                    "A faster, safer, and genuinely simpler alternative to Ansible and Salt. "
                    "No YAML. No agents. No surprises — "
                    span { class: "font-semibold text-zinc-200", "you write Rust. That's it." }
                }

                div { class: "mt-9 flex flex-col items-center justify-center gap-3 sm:flex-row",
                    a {
                        href: "#demo",
                        class: "w-full rounded-xl bg-ember-500 px-6 py-3 text-base font-semibold text-ink transition-all hover:bg-ember-400 hover:shadow-lg hover:shadow-ember-500/20 sm:w-auto",
                        "See it in action"
                    }
                    Link {
                        to: Route::Docs {},
                        class: "w-full rounded-xl border border-line bg-panel/60 px-6 py-3 text-base font-semibold text-zinc-100 transition-colors hover:border-zinc-600 sm:w-auto",
                        "Read the docs"
                    }
                }
            }
        }
    }
}

#[component]
pub fn Example() -> Element {
    rsx! {
        section { id: "example", class: "border-b border-line/60",
            div { class: "mx-auto max-w-5xl px-5 pb-16 pt-20 sm:px-8 sm:pb-20 sm:pt-28",
                div { class: "mx-auto max-w-2xl text-center",
                    h2 { class: "text-3xl font-bold tracking-tight sm:text-4xl",
                        "Your whole infra, in one language."
                    }
                    p { class: "mt-4 text-lg text-zinc-400",
                        "Define an inventory, write the work as ordinary Rust, and run it. "
                        "The compiler catches syntax errors before any host does."
                    }
                }

                div { class: "mt-12 overflow-hidden rounded-2xl border border-line bg-ink-soft shadow-2xl shadow-black/40",
                    div { class: "flex items-center gap-2 border-b border-line bg-panel px-4 py-3",
                        span { class: "h-3 w-3 rounded-full bg-red-500/80" }
                        span { class: "h-3 w-3 rounded-full bg-yellow-500/80" }
                        span { class: "h-3 w-3 rounded-full bg-green-500/80" }
                        span { class: "ml-2 font-mono text-xs text-zinc-500", "src/main.rs" }
                    }
                    dioxus_code::Code {
                        src: dioxus_code::code!("../cindy/examples/website-minimal/src/main.rs"),
                        theme: dioxus_code::Theme::AYU_DARK,
                    }
                }
                div { class: "mx-auto max-w-2xl text-center",
                    p { class: "mt-8 text-lg text-zinc-400",
                        "That's the whole program. Run it against any slice of your fleet."
                    }
                }

                div { class: "mt-6 overflow-hidden rounded-xl border border-line bg-ink-soft",
                    div { class: "flex items-center gap-2 border-b border-line bg-panel px-4 py-2.5",
                        span { class: "ml-1 font-mono text-xs text-zinc-500", "shell" }
                    }
                    div { class: "overflow-x-auto font-mono text-sm leading-relaxed",
                        dioxus_code::Code {
                            src: dioxus_code::code_str!(
                                "$ cindy play --limit proxy",
                                dioxus_code::CodeOptions::builder()
                                    .with_language(dioxus_code::Language::Bash)
                            ),
                            theme: dioxus_code::Theme::AYU_DARK,
                        }
                    }
                }
            }
        }
    }
}

/// The recorded terminal demo, played by asciinema-player (loaded from the
/// CDN in `main.rs`). The player is a third-party JS widget, so we mount an
/// empty target `div` and, once it's in the DOM, drive `AsciinemaPlayer.create`
/// via `document::eval`. We poll briefly because the CDN script may still be
/// loading when this effect first runs.
#[component]
pub fn Demo() -> Element {
    // Hashed URL of the recording, resolved at compile time.
    const CAST: Asset = asset!("/assets/demo.cast");

    use_effect(move || {
        let src = CAST.to_string();
        let _ = document::eval(&format!(
            r#"
            const src = "{src}";
            const mount = () => {{
                const el = document.getElementById("demo-player");
                if (!el || !window.AsciinemaPlayer) {{ setTimeout(mount, 60); return; }}
                if (el.dataset.ready) return;          // guard against re-init
                el.dataset.ready = "1";
                window.AsciinemaPlayer.create(src, el, {{
                    autoPlay: true,
                    loop: true,
                    preload: true,
                    poster: "npt:0:02",
                    fit: "width",
                }});
            }};
            mount();
            "#,
        ));
    });

    rsx! {
        section { id: "demo", class: "border-b border-line/60",
            div { class: "mx-auto max-w-5xl px-5 py-20 sm:px-8 sm:py-28",
                div { class: "mx-auto max-w-2xl text-center",
                    h2 { class: "text-3xl font-bold tracking-tight sm:text-4xl",
                        "See it run."
                    }
                    p { class: "mt-4 text-lg text-zinc-400",
                        "A real run against a host, recorded in the terminal."
                    }
                }

                div { class: "mt-12 overflow-hidden rounded-2xl border border-line bg-ink-soft shadow-2xl shadow-black/40",
                    div { class: "flex items-center gap-2 border-b border-line bg-panel px-4 py-3",
                        span { class: "h-3 w-3 rounded-full bg-red-500/80" }
                        span { class: "h-3 w-3 rounded-full bg-yellow-500/80" }
                        span { class: "h-3 w-3 rounded-full bg-green-500/80" }
                        span { class: "ml-2 font-mono text-xs text-zinc-500" }
                    }
                    // asciinema-player mounts its terminal here.
                    div { id: "demo-player", class: "p-2" }
                }
            }
        }
    }
}

struct Feature {
    title: &'static str,
    body: &'static str,
    /// Which line-icon to render in the card's badge.
    icon: Icon,
}

const FEATURES: &[Feature] = &[
    Feature {
        title: "Plain Rust",
        body: "No DSL, no Jinja, no YAML. Your plays are real code with real types, real functions, and real tooling — no more mid-deploy failures on a syntax error.",
        icon: Icon::Code,
    },
    Feature {
        title: "Fast by default",
        body: "Hosts are provisioned concurrently and everything is native machine code. One binary gets transferred, and everything else happens via stdio.",
        icon: Icon::Bolt,
    },
    Feature {
        title: "Secret management",
        body: "Write secrets inline in your inventory or code. The CLI's seal step encrypts them in place into a vault-tagged blob you can safely commit.",
        icon: Icon::Lock,
    },
    Feature {
        title: "Agent-less",
        body: "Cindy ships a single binary that runs itself on the remote over SSH and communicates with another binary running on your host machine. Nothing to install or keep updated on your fleet.",
        icon: Icon::Link,
    },
    Feature {
        title: "Idempotent builtins",
        body: "Files, packages, services, users, and groups all reconcile to a desired state and tell you exactly what changed.",
        icon: Icon::Refresh,
    },
    Feature {
        title: "Observability",
        body: "Watch every host live in the terminal UI: per-host output, status at a glance.",
        icon: Icon::Eye,
    },
];

/// A small set of line icons drawn inline (no asset round-trip), one per
/// feature card. All share a 24×24 view box and the `currentColor`
/// stroke so they inherit the badge's ember tint.
#[derive(Clone, Copy, PartialEq)]
enum Icon {
    Code,
    Bolt,
    Lock,
    Link,
    Refresh,
    Eye,
}

#[component]
fn FeatureIcon(icon: Icon) -> Element {
    // Common stroke styling for every glyph.
    let body = match icon {
        // `</>` — plain Rust / real code.
        Icon::Code => rsx! {
            path { d: "M9 18l-6-6 6-6" }
            path { d: "M15 6l6 6-6 6" }
        },
        // Lightning bolt — fast by default.
        Icon::Bolt => rsx! {
            path { d: "M13 2L4 14h7l-1 8 9-12h-7l1-8z" }
        },
        // Padlock with a keyhole — secret management.
        Icon::Lock => rsx! {
            rect { x: "4", y: "10", width: "16", height: "11", rx: "2" }
            path { d: "M8 10V7a4 4 0 0 1 8 0v3" }
            path { d: "M12 14v3" }
        },
        // Chain link — agent-less SSH connection between two binaries.
        Icon::Link => rsx! {
            path { d: "M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1" }
            path { d: "M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1" }
        },
        // Circular arrows — idempotent reconcile.
        Icon::Refresh => rsx! {
            path { d: "M21 12a9 9 0 0 1-9 9 9 9 0 0 1-8-5" }
            path { d: "M3 12a9 9 0 0 1 9-9 9 9 0 0 1 8 5" }
            path { d: "M21 3v5h-5" }
            path { d: "M3 21v-5h5" }
        },
        // Eye — observability / watch every host live.
        Icon::Eye => rsx! {
            path { d: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" }
            circle { cx: "12", cy: "12", r: "3" }
        },
    };

    rsx! {
        svg {
            class: "h-5 w-5",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            stroke_width: "1.75",
            stroke_linecap: "round",
            stroke_linejoin: "round",
            xmlns: "http://www.w3.org/2000/svg",
            {body}
        }
    }
}

#[component]
pub fn Features() -> Element {
    rsx! {
        section { id: "features", class: "border-b border-line/60",
            div { class: "mx-auto max-w-6xl px-5 pb-20 pt-16 sm:px-8 sm:pb-28 sm:pt-20",
                div { class: "max-w-2xl",
                    p { class: "text-sm font-semibold uppercase tracking-widest text-ember-400",
                        "Why Cindy"
                    }
                    h2 { class: "mt-3 text-3xl font-bold tracking-tight sm:text-4xl",
                        "Everything you liked about Ansible, minus the parts that hurt."
                    }
                    p { class: "mt-4 text-lg text-zinc-400",
                        "Agent-less and idempotent — but type-checked, fast, and "
                        "written entirely in a language you (might) already know."
                    }
                }

                div { class: "mt-14 grid gap-px overflow-hidden rounded-2xl border border-line bg-line sm:grid-cols-2 lg:grid-cols-3",
                    for feature in FEATURES {
                        div { class: "group bg-ink-soft p-7 transition-colors hover:bg-panel",
                            div { class: "mb-4 inline-flex h-9 w-9 items-center justify-center rounded-lg bg-ember-500/10 text-ember-400 ring-1 ring-ember-500/20",
                                FeatureIcon { icon: feature.icon }
                            }
                            h3 { class: "text-lg font-semibold text-white", "{feature.title}" }
                            p { class: "mt-2 text-sm leading-relaxed text-zinc-400", "{feature.body}" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn Cta() -> Element {
    rsx! {
        section { class: "relative overflow-hidden",
            div { class: "pointer-events-none absolute inset-0 bg-ember-glow" }
            div { class: "relative mx-auto max-w-3xl px-5 py-24 text-center sm:px-8 sm:py-32",
                h2 { class: "mt-6 text-balance text-4xl font-extrabold tracking-tight sm:text-5xl",
                    "Stop fighting your tools."
                }
                p { class: "mx-auto mt-4 max-w-xl text-lg text-zinc-400",
                    "Add Cindy to a Cargo project and provision your first host in minutes."
                }
                div { class: "mt-8 inline-flex items-center gap-3 rounded-xl border border-line bg-ink-soft font-mono text-sm overflow-hidden",
                    dioxus_code::Code {
                        src: dioxus_code::code_str!(
                            "$ cargo install cindy-cli",
                            dioxus_code::CodeOptions::builder()
                                .with_language(dioxus_code::Language::Bash)
                        ),
                        theme: dioxus_code::Theme::AYU_DARK,
                    }
                }
                div { class: "mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row",
                    Link {
                        to: Route::Docs {},
                        class: "inline-block rounded-xl bg-ember-500 px-7 py-3 text-base font-semibold text-ink transition-all hover:bg-ember-400 hover:shadow-lg hover:shadow-ember-500/20",
                        "Get started"
                    }
                    a {
                        href: REPO,
                        class: "inline-block rounded-xl border border-line bg-panel/60 px-7 py-3 text-base font-semibold text-zinc-100 transition-colors hover:border-zinc-600",
                        "Browse the source"
                    }
                }
            }
        }
    }
}

#[component]
pub fn Footer() -> Element {
    rsx! {
        footer { class: "border-t border-line/60",
            div { class: "mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 px-5 py-10 sm:flex-row sm:px-8",
                div { class: "flex items-center gap-2.5 text-sm text-zinc-400",
                    Spark { class: "h-5 w-5" }
                    span { "Cindy — managing infrastructure at breakneck speed." }
                }
                div { class: "flex items-center gap-6 text-sm text-zinc-400",
                    a { href: DISCORD, class: "transition-colors hover:text-white", "Discord" }
                    a { href: REPO, class: "transition-colors hover:text-white", "Source" }
                    span { class: "text-zinc-600", "GPLv3" }
                }
            }
        }
    }
}
