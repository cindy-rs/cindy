//! Remote fns that live in the playbook's *library* rather than next
//! to `#[cindy::main]` — the layout a playbook grows into once its
//! roles get their own modules. Nothing in the worker build's
//! `main.rs` names this crate, so the worker only carries these fns
//! because `#[cindy::main]` links the package's lib itself.

#[cindy::remote]
pub fn lib_side_echo(word: String) -> cindy::Result<String> {
    Ok(format!("lib:{word}"))
}
