//! The long-form Getting Started / reference page (`/docs`).
//!
//! Content is written against the *current* repo state (targeting the 0.2.0
//! release), verified from the cindy sources: the CLI binary is `cindy` from
//! the `cindy-cli` crate; the run subcommand is `cindy play`; the worker is
//! cross-compiled with `cross` to `<arch>-unknown-linux-musl`.

use dioxus::prelude::*;
use dioxus_code::Theme;
use dioxus_code::advanced::HighlightedSource;

use crate::sections::{Footer, Nav};

const REPO: &str = "https://github.com/cindy-rs/cindy";

/// A code snippet in a styled card. `dioxus-code` highlights at compile time
/// (the runtime highlighter can't link on wasm), so callers build `src` with
/// the `code!`/`code_str!` macros and hand the result here.
#[component]
fn Snippet(src: HighlightedSource) -> Element {
    rsx! {
        div { class: "mt-4 overflow-hidden rounded-xl border border-line bg-ink-soft",
            div { class: "overflow-x-auto text-sm leading-relaxed",
                dioxus_code::Code { src, theme: Theme::AYU_DARK }
            }
        }
    }
}

/// Build a Bash snippet's highlighted source from an inline literal.
macro_rules! shell {
    ($code:literal) => {
        dioxus_code::code_str!(
            $code,
            dioxus_code::CodeOptions::builder().with_language(dioxus_code::Language::Bash)
        )
    };
}

/// A section heading with an `id` for the TOC to anchor to.
#[component]
fn H2(id: String, title: String) -> Element {
    rsx! {
        h2 {
            id,
            class: "scroll-mt-20 mt-16 border-b border-line/60 pb-2 text-2xl font-bold tracking-tight text-white first:mt-0 sm:text-3xl",
            title
        }
    }
}

#[component]
fn H3(title: String) -> Element {
    rsx! {
        h3 { class: "mt-10 text-lg font-semibold text-white", title }
    }
}

/// A paragraph of body copy.
#[component]
fn P(children: Element) -> Element {
    rsx! {
        p { class: "mt-4 leading-relaxed text-zinc-400", {children} }
    }
}

struct TocItem {
    href: &'static str,
    label: &'static str,
}

const TOC: &[TocItem] = &[
    TocItem {
        href: "#install",
        label: "Installation",
    },
    TocItem {
        href: "#quickstart",
        label: "Quick start",
    },
    TocItem {
        href: "#secrets",
        label: "Secrets",
    },
    TocItem {
        href: "#remote-actions",
        label: "Remote & actions",
    },
    TocItem {
        href: "#async",
        label: "Async & sync",
    },
    TocItem {
        href: "#builtins",
        label: "Builtins",
    },
];

#[component]
pub fn Docs() -> Element {
    rsx! {
        div { class: "min-h-screen flex flex-col",
            Nav {}
            div { class: "mx-auto flex w-full max-w-6xl flex-1 gap-12 px-5 py-12 sm:px-8 sm:py-16",
                // Sticky table of contents (desktop only).
                aside { class: "hidden w-48 shrink-0 lg:block",
                    nav { class: "sticky top-24 space-y-1 text-sm",
                        p { class: "mb-3 text-xs font-semibold uppercase tracking-widest text-ember-400",
                            "On this page"
                        }
                        for item in TOC {
                            a {
                                href: item.href,
                                class: "block rounded px-2 py-1 text-zinc-400 transition-colors hover:bg-panel hover:text-white",
                                "{item.label}"
                            }
                        }
                    }
                }

                main { class: "min-w-0 max-w-3xl flex-1",
                    DocsHeader {}
                    Installation {}
                    QuickStart {}
                    Secrets {}
                    RemoteAndActions {}
                    AsyncSync {}
                    Builtins {}
                }
            }
            Footer {}
        }
    }
}

#[component]
fn DocsHeader() -> Element {
    rsx! {
        p { class: "text-sm font-semibold uppercase tracking-widest text-ember-400", "Documentation" }
        h1 { class: "mt-3 text-4xl font-extrabold tracking-tight text-white sm:text-5xl",
            "Getting started"
        }
        P {
            "Cindy is configuration management written entirely in Rust. You declare your "
            "fleet and your tasks as ordinary code; the compiler checks it, and a single "
            "statically-linked binary is shipped to each host over SSH and run there. This "
            "page takes you from an empty project to a working deploy, then covers secrets, "
            "the remote/action model, and every builtin."
        }
    }
}

#[component]
fn Installation() -> Element {
    rsx! {
        H2 { id: "install", title: "Installation" }
        P {
            "Cindy has two halves: the "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "cindy" }
            " command-line tool, and the "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "cindy" }
            " library you add to your project. The CLI compiles your project twice — once for "
            "your machine (the orchestrator) and once for the remote host (the worker) — so it "
            "needs a working Rust toolchain and a cross-compiler."
        }

        H3 { title: "1. Toolchain" }
        P {
            "Install Rust via "
            a { href: "https://rustup.rs", class: "text-ember-400 hover:underline", "rustup" }
            ". Cindy builds on stable Rust (edition 2024; 1.98 or newer)."
        }
        Snippet { src: shell!("$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh") }

        H3 { title: "2. Cross-compiler" }
        P {
            "The worker binary is cross-compiled to a statically-linked musl target "
            "("
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "<arch>-unknown-linux-musl" }
            "), so it runs on the remote with nothing to install there. Cindy drives this with "
            a { href: "https://github.com/cross-rs/cross", class: "text-ember-400 hover:underline", "cross" }
            ", which needs Docker or Podman."
        }
        Snippet { src: shell!("$ cargo install cross\n# and a container engine, e.g. Docker or Podman, running locally") }

        H3 { title: "3. The cindy CLI" }
        P { "Install the command-line tool. The binary is named "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "cindy" }
            "."
        }
        Snippet { src: shell!("$ cargo install cindy-cli") }
        P {
            "Or build it straight from the repository:"
        }
        Snippet { src: shell!("$ cargo install --git https://github.com/cindy-rs/cindy cindy-cli") }

        H3 { title: "What the remote needs" }
        P {
            "Almost nothing. The host only needs an SSH server you can reach (Cindy uses your "
            "regular SSH config and host aliases) and a POSIX shell. There is no agent, daemon, "
            "or Python to install — the cross-compiled binary is self-contained, and privileged "
            "steps escalate through "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "sudo" }
            " unless you pass "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "--unprivileged" }
            "."
        }
    }
}

#[component]
fn QuickStart() -> Element {
    rsx! {
        H2 { id: "quickstart", title: "Quick start" }
        P {
            "Create a normal Cargo binary project and add the library. Cindy compiles the same "
            "crate with two different feature flags, so add both as needed by the tool:"
        }
        Snippet { src: shell!("$ cargo new deploy && cd deploy\n$ cargo add cindy") }

        P {
            "A Cindy program has three parts: a "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::inventory]" }
            " describing your hosts, optional "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::remote]" }
            " functions that run on the host, and a "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::main]" }
            " that does the work for one host. Here is a minimal "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "src/main.rs" }
            ":"
        }
        Snippet { src: dioxus_code::code!("src/snippets/quickstart.rs") }

        P { "Then run it, selecting hosts by tag:" }
        Snippet { src: shell!("$ cindy play --limit proxy") }
        P {
            "The "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "--limit" }
            " expression supports "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "&" }
            " (and), "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "|" }
            " (or), "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "!" }
            " (not) and parentheses over tag/name terms, e.g. "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200",
                "--limit 'location:prague & !service:nginx'"
            }
            ". To inspect what Cindy sees without deploying, use "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "cindy inventory" }
            " (add "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "--json" }
            " or "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "--host <name>" }
            ")."
        }
    }
}

#[component]
fn Secrets() -> Element {
    rsx! {
        H2 { id: "secrets", title: "Secrets" }
        P {
            "Secrets live inline in your code as "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "Secret<T>" }
            ", written with the "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "secret!" }
            " macro. The first argument names a vault; the second is the value (a literal or "
            "other self-contained expression — no captured locals):"
        }
        Snippet { src: dioxus_code::code!("src/snippets/secret.rs") }

        P {
            "While unsealed, a secret is just the plain value (and the build warns you). Create "
            "the vault key once, then seal — Cindy rewrites every "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "secret!" }
            " in your source into an encrypted, vault-tagged blob that is safe to commit:"
        }
        Snippet { src: shell!("$ cindy secret vault create prod   # writes keys/prod.dek (gitignored)\n$ cindy secret seal --all          # encrypts every secret! in place") }
        P {
            "After sealing, the call becomes "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200",
                "Secret::sealed_b64(\"prod\", \"AAAA…\")"
            }
            ". To get the editable form back, run "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "cindy secret unseal --all" }
            "."
        }

        H3 { title: "Using a secret" }
        P {
            "At runtime, call "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", ".reveal()" }
            " to decrypt. The vault's data-encryption key is supplied to the orchestrator out of "
            "band and forwarded to the worker over the encrypted SSH channel — never through the "
            "target's environment or arguments. Secrets refuse to print their plaintext via "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "Debug" }
            ", and the decrypted bytes are zeroized after use."
        }
        Snippet { src: dioxus_code::code!("src/snippets/reveal.rs") }
        P {
            "The "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "keys/*.dek" }
            " files are the only thing you must keep out of version control; everything else, "
            "including the ciphertext, is safe to commit."
        }
    }
}

#[component]
fn RemoteAndActions() -> Element {
    rsx! {
        H2 { id: "remote-actions", title: "Remote & actions" }
        P {
            "Code in "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::main]" }
            " runs on the orchestrator (your machine). To run code "
            span { class: "italic", "on the host" }
            ", annotate a function with "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::remote]" }
            " and call it. The call returns a future you "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", ".await" }
            "; the arguments and return value are serialized over the SSH pipe, so they must be "
            "serializable (use "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::wire]" }
            " on your own types). Remote functions cannot be generic."
        }
        Snippet { src: dioxus_code::code!("src/snippets/remote.rs") }

        H3 { title: "#[cindy::wire]" }
        P {
            "Any type that crosses the wire — host vars, remote arguments, return values — needs "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::wire]" }
            ", which derives "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "Debug" }
            ", "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "Serialize" }
            " and "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "Deserialize" }
            ". Don't also derive "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "Debug" }
            " yourself — "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "wire" }
            " already adds it."
        }

        H3 { title: "#[cindy::action]" }
        P {
            "Most builtins are "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::action]" }
            " functions: an ergonomic wrapper around a remote call. An action takes "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "impl Into<T>" }
            " arguments (so you can pass "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "&str" }
            " literals directly) and, from one function body, generates the concrete "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[remote]" }
            " entry point plus the call-site shim. Write your own when you want a tidy, "
            "intent-named verb over a lower-level remote — exactly how the systemd helpers wrap a "
            "single state-applying remote:"
        }
        Snippet { src: dioxus_code::code!("src/snippets/action.rs") }
    }
}

#[component]
fn AsyncSync() -> Element {
    rsx! {
        H2 { id: "async", title: "Async & sync" }
        P {
            "Both "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::remote]" }
            " and "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::action]" }
            " work on either a sync or an async function — the macro detects "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "async" }
            " from the signature. A synchronous body is run on a blocking thread on the worker, "
            "so you can call ordinary blocking code without stalling the runtime. Regardless of "
            "the body, the orchestrator-side call is always a future you "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", ".await" }
            "."
        }
        Snippet { src: dioxus_code::code!("src/snippets/async.rs") }
        P {
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::main]" }
            " and "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "#[cindy::inventory]" }
            " may likewise be sync or async."
        }
    }
}

#[component]
fn Builtins() -> Element {
    rsx! {
        H2 { id: "builtins", title: "Builtins" }
        P {
            "Builtins live under "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "cindy::builtin" }
            " and run on the host. Most are idempotent and return "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "Result<Return>" }
            ", where "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "Return::changed()" }
            " tells you whether anything actually changed — handy for chaining (\"if the config "
            "changed, restart the service\"). Each module offers intent-named helpers for the "
            "common cases and, where useful, a full-control "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "State" }
            " entry point."
        }

        for m in BUILTINS {
            div { class: "mt-10 overflow-hidden rounded-xl border border-line bg-ink-soft",
                div { class: "border-b border-line bg-panel px-4 py-2.5",
                    span { class: "font-mono text-sm font-semibold text-ember-400", "{m.path}" }
                    span { class: "ml-2 text-sm text-zinc-400", "{m.summary}" }
                }
                table { class: "w-full text-left text-sm",
                    tbody {
                        for f in m.fns {
                            tr { class: "border-b border-line/40 last:border-0 align-top",
                                td { class: "whitespace-nowrap px-4 py-2.5 font-mono text-xs text-zinc-200",
                                    "{f.sig}"
                                }
                                td { class: "px-4 py-2.5 text-zinc-400", "{f.desc}" }
                            }
                        }
                    }
                }
            }
        }

        P {
            "Run a process directly with "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "command" }
            ", or escape to anything not yet covered. For the exact type definitions (the "
            code { class: "rounded bg-panel px-1.5 py-0.5 font-mono text-sm text-zinc-200", "State" }
            " structs and their fields), see the source."
        }
        div { class: "mt-4",
            a {
                href: REPO,
                class: "inline-block rounded-xl border border-line bg-panel/60 px-6 py-3 font-semibold text-zinc-100 transition-colors hover:border-zinc-600",
                "Browse the source"
            }
        }
    }
}

struct BuiltinFn {
    sig: &'static str,
    desc: &'static str,
}

struct BuiltinModule {
    path: &'static str,
    summary: &'static str,
    fns: &'static [BuiltinFn],
}

const BUILTINS: &[BuiltinModule] = &[
    BuiltinModule {
        path: "path",
        summary: "files, directories, symlinks, and removal",
        fns: &[
            BuiltinFn {
                sig: "file(dest, content, user, group, mode)",
                desc: "Manage a regular file with the given contents, owner, and mode.",
            },
            BuiltinFn {
                sig: "directory(dest, user, group, mode)",
                desc: "Manage a directory with the given owner and mode.",
            },
            BuiltinFn {
                sig: "link(dest, target, user, group)",
                desc: "Manage a symbolic link to target.",
            },
            BuiltinFn {
                sig: "absent(dest)",
                desc: "Ensure nothing exists at the path (recursively removes directories).",
            },
        ],
    },
    BuiltinModule {
        path: "systemd",
        summary: "manage a unit (boot + runtime axes)",
        fns: &[
            BuiltinFn {
                sig: "enable / disable / mask (name)",
                desc: "Set the boot-time enablement of a unit.",
            },
            BuiltinFn {
                sig: "start / stop / restart / reload (name)",
                desc: "Drive the runtime (active) state of a unit.",
            },
            BuiltinFn {
                sig: "enable_and_start / disable_and_stop (name)",
                desc: "Both axes at once for the common cases.",
            },
            BuiltinFn {
                sig: "systemd(State)",
                desc: "Full control over both enablement and runtime.",
            },
            BuiltinFn {
                sig: "daemon_reload()",
                desc: "Re-read unit files from disk (after writing one yourself).",
            },
        ],
    },
    BuiltinModule {
        path: "debian::apt",
        summary: "manage a single apt package",
        fns: &[
            BuiltinFn {
                sig: "install(name)",
                desc: "Ensure the package is installed at any version.",
            },
            BuiltinFn {
                sig: "install_version(name, version)",
                desc: "Ensure an exact dpkg version is installed.",
            },
            BuiltinFn {
                sig: "hold(name, version)",
                desc: "Install an exact version, then apt-mark hold it.",
            },
            BuiltinFn {
                sig: "remove / purge (name)",
                desc: "Remove the package (purge also drops config files).",
            },
            BuiltinFn {
                sig: "apt(State)",
                desc: "Full control over presence and hold state.",
            },
        ],
    },
    BuiltinModule {
        path: "user",
        summary: "manage a Unix user account",
        fns: &[BuiltinFn {
            sig: "user(State)",
            desc: "Create, modify, or remove a user (uid, groups, shell, home, pre-hashed password, …).",
        }],
    },
    BuiltinModule {
        path: "group",
        summary: "manage a Unix group",
        fns: &[BuiltinFn {
            sig: "group(State)",
            desc: "Create, modify, or remove a group (optional gid, system flag).",
        }],
    },
    BuiltinModule {
        path: "command",
        summary: "run a process or script",
        fns: &[
            BuiltinFn {
                sig: "command(argv, State)",
                desc: "Run a program directly, without a shell. Returns its Output.",
            },
            BuiltinFn {
                sig: "shell(interpreter, script, State)",
                desc: "Run a script through an explicit interpreter. Returns its Output.",
            },
        ],
    },
    BuiltinModule {
        path: "fetch",
        summary: "download a file over HTTP(S)",
        fns: &[BuiltinFn {
            sig: "fetch(State)",
            desc: "Download to the host, verifying a sha256/sha512 checksum if given (which also makes it idempotent).",
        }],
    },
    BuiltinModule {
        path: "archive / unarchive",
        summary: "create and extract archives",
        fns: &[
            BuiltinFn {
                sig: "archive(State)",
                desc: "Create a tar/tar.gz/tar.xz/tar.zst/zip/7z archive from source paths.",
            },
            BuiltinFn {
                sig: "unarchive(State)",
                desc: "Extract an archive into a directory (format inferred from the extension).",
            },
        ],
    },
    BuiltinModule {
        path: "compress / decompress",
        summary: "in-memory byte buffers",
        fns: &[
            BuiltinFn {
                sig: "compress(data, codec)",
                desc: "Compress bytes with Store/Gzip/Xz/Zstd.",
            },
            BuiltinFn {
                sig: "decompress(data, codec)",
                desc: "Decompress bytes with the matching codec.",
            },
        ],
    },
];
