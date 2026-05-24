use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{FnArg, Item, ItemFn, Pat, PatIdent, parse_macro_input};

/// Given an argument type, if it's `impl Into<T>` return `Some(T)`; otherwise
/// `None` (the type is used as-is for the concrete raw fn).
fn into_target(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::ImplTrait(it) = ty else {
        return None;
    };
    for bound in &it.bounds {
        let syn::TypeParamBound::Trait(tb) = bound else {
            continue;
        };
        let seg = tb.path.segments.last()?;
        if seg.ident != "Into" {
            continue;
        }
        if let syn::PathArguments::AngleBracketed(args) = &seg.arguments
            && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
        {
            return Some(inner.clone());
        }
    }
    None
}

/// A spanned compile error, so misuse diagnostics point at the
/// offending tokens instead of the whole attribute.
fn compile_err(span: proc_macro2::Span, msg: &str) -> TokenStream {
    syn::Error::new(span, msg).to_compile_error().into()
}

/// Reject argument types that cannot cross the RPC wire, with a
/// message at the argument's span. Only top-level `impl Trait` and
/// references are checked — the realistic misuses; anything more exotic
/// still fails in the generated code.
fn check_remote_arg(ty: &syn::Type) -> Option<&'static str> {
    match ty {
        syn::Type::ImplTrait(_) => Some(
            "`impl Trait` arguments are not allowed in `#[cindy::remote]` fns — use a \
             concrete type (`#[cindy::action]` supports `impl Into<T>`)",
        ),
        syn::Type::Reference(_) => Some(
            "reference arguments are not allowed in `#[cindy::remote]` fns — arguments \
             cross the wire and must be owned (e.g. `String` instead of `&str`)",
        ),
        _ => None,
    }
}

/// Shorthand for deriving `Debug` and `serde::{Deserialize, Serialize}`
/// without an explicit `serde` dependency.
///
/// `Debug` is included because inventory `vars` types need it (so
/// `cindy inventory` can render them). Don't also list `Debug` in a
/// manual `#[derive(...)]` on the same item — that's a duplicate impl.
#[proc_macro_attribute]
pub fn wire(_args: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as Item);

    quote! {
        #[derive(
            ::std::fmt::Debug,
            cindy::__reexports::serde::Serialize,
            cindy::__reexports::serde::Deserialize
        )]
        #[serde(crate = "cindy::__reexports::serde")]
        #item
    }
    .into()
}

/// Specifies an entrypoint.
///
/// - On `feature = "orchestrator"`
///   - Compiles to normal program.
/// - On `feature = "remote"`
///   - Runs a RPC loop instead.
///
/// The user's `main` may be declared in one of two shapes:
///
/// 1. `async fn main() -> Result<()>` - legacy, no host context.
/// 2. `async fn main(host: cindy::Host<V>) -> Result<()>` - the macro
///    reads the `CINDY_HOST_CONTEXT` env var (JSON serialized
///    `cindy::Host<V>` produced by the CLI for this particular target)
///    and hands it pre-parsed to the body. Any `Serialize +
///    DeserializeOwned` `V` works; use `cindy::Host<()>` if you only
///    need `name`/`tags`.
///
/// The `async` keyword is optional either way: the body is always
/// spliced into an async context, so a plain `fn main` can still
/// `.await` remote calls.
#[proc_macro_attribute]
pub fn main(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);

    let (attrs, vis, sig, block) = (&input.attrs, &input.vis, &input.sig, &input.block);
    let output = &sig.output;
    let inputs = &sig.inputs;

    let invoke_user_main = match inputs.len() {
        0 => quote! {
            cindy::__reexports::tokio::spawn(__user_main())
        },
        1 => match &inputs[0] {
            // The host type is inferred from `__user_main`'s signature,
            // so `entry::host_context` needs no explicit turbofish.
            FnArg::Typed(_) => quote! {
                cindy::__reexports::tokio::spawn(__user_main(cindy::entry::host_context()))
            },
            FnArg::Receiver(r) => {
                return compile_err(
                    syn::spanned::Spanned::span(r),
                    "`#[cindy::main]` cannot take `self`",
                );
            }
        },
        _ => {
            return compile_err(
                syn::spanned::Spanned::span(inputs),
                "`#[cindy::main]` accepts at most one parameter (the host context, `cindy::Host<V>`)",
            );
        }
    };

    quote! {
        #(#attrs)*
        #[cindy::__reexports::tokio::main(crate = "cindy::__reexports::tokio")]
        #vis async fn main() {
            // A featureless build used to compile to a silent no-op
            // `main`; catch it at compile time instead. The `cindy`
            // CLI always builds with exactly one of the two features;
            // for plain `cargo check` and rust-analyzer, declare
            // `default = ["orchestrator", "remote"]` in your [features]
            // so both halves of the program are analysed.
            #[cfg(not(any(feature = "orchestrator", feature = "remote")))]
            ::core::compile_error!(
                "a cindy binary must be built with the `orchestrator` or `remote` feature \
                 (add `default = [\"orchestrator\", \"remote\"]` to [features] for plain \
                 `cargo check`)"
            );

            #[allow(unused_variables)]
            let (rpc_in, rpc_out) = cindy::common::quarantine_stdio();

            // Remote-only builds skip the user's body entirely; the
            // worker just runs the RPC dispatch loop. Vault keys arrive
            // over the channel's first frame (the handshake) — they
            // never touch this process's argv/env, so they're invisible
            // in the target's `ps`.
            #[cfg(all(feature = "remote", not(feature = "orchestrator")))]
            {
                cindy::remote::rpc(rpc_in, rpc_out).await;
                ::std::process::exit(0);
            }

            // Orchestrator builds (and dual-feature LSP builds) serve
            // the CLI side modes / set up the RPC plumbing (see
            // `cindy::entry::orchestrator_init`), then run the user's
            // body. Using a *positive* cfg here — rather than
            // `not(remote)` — keeps the body in scope when both
            // features are enabled at once, which is how rust-analyzer
            // typically evaluates this workspace.
            #[cfg(feature = "orchestrator")]
            {
                async fn __user_main(#inputs) #output #block

                cindy::entry::orchestrator_init(rpc_in, rpc_out).await;

                match #invoke_user_main.await {
                    ::std::result::Result::Ok(::std::result::Result::Ok(_)) => {
                        ::std::process::exit(0);
                    }
                    ::std::result::Result::Ok(::std::result::Result::Err(e)) => {
                        ::std::eprintln!("\x1b[31m{:?}\x1b[0m", e);
                        ::std::process::exit(1);
                    }
                    ::std::result::Result::Err(_) => {
                        ::std::process::exit(1);
                    }
                };
            }
        }
    }
    .into()
}

/// Registers an inventory function.
///
/// Exactly one `#[cindy::inventory]` should exist per binary. The function
/// may be named in any way, can be sync or async, and may return either
/// `cindy::Inventory<V>` or `cindy::Result<cindy::Inventory<V>>`.
///
/// ```rust,ignore
/// #[cindy::wire]
/// struct MyVars {
///     var_a: u64,
///     var_b: String,
/// }
///
/// #[cindy::inventory]
/// async fn inventory() -> cindy::Result<cindy::Inventory<MyVars>> {
///     Ok(cindy::Inventory {
///         hosts: vec![
///             cindy::Host {
///                 name: "host-01".into(),
///                 tags: cindy::tags!["env:production", "continent:eu", "router"],
///                 vars: MyVars { var_a: 42, var_b: "hello".to_string() },
///             },
///         ],
///     })
/// }
/// ```
#[proc_macro_attribute]
pub fn inventory(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);

    let (attrs, vis, sig, block) = (&input.attrs, &input.vis, &input.sig, &input.block);
    let function_ident = &sig.ident;
    let asyncness = &sig.asyncness;
    let output = &sig.output;
    let inputs = &sig.inputs;

    if !inputs.is_empty() {
        return compile_err(
            syn::spanned::Spanned::span(inputs),
            "`#[cindy::inventory]` functions must take no arguments",
        );
    }

    let invocation = if asyncness.is_some() {
        quote! { #function_ident().await }
    } else {
        quote! {
            match cindy::__reexports::tokio::task::spawn_blocking(move || #function_ident())
                .await
            {
                Ok(v) => v,
                Err(je) => ::std::panic::resume_unwind(je.into_panic()),
            }
        }
    };

    quote! {
        #(#attrs)*
        #vis #asyncness fn #function_ident () #output #block

        cindy::__reexports::inventory::submit! {
            cindy::inventory::RegisteredInventory {
                dump: || ::std::boxed::Box::pin(async move {
                    cindy::inventory::IntoInventoryDump::into_inventory_dump(#invocation)
                }),
            }
        }
    }
    .into()
}

/// Marks a function as "running on the remote host".
///
/// Each `#[cindy::remote] fn foo(args) -> T` expands to a small bundle of
/// items at the same path:
///
/// 1. **`fn foo(args) -> impl Future<Output = T>`** — the RPC shim used by
///    `#[cindy::main]` and other orchestrator-side code. Dispatches the call
///    eagerly and resolves once the worker has replied. (Lives in the value
///    namespace.)
/// 2. **`enum foo {} + impl foo { fn inner(args) -> T { ..user body.. } }`** -
///    the actual body, exposed at `foo::inner(args)`. Used inside other
///    `#[remote]` bodies on the worker to call siblings directly without
///    going through the RPC channel. The enum is uninhabited; it exists
///    purely so the path syntax `foo::inner` works in the type namespace,
///    side-by-side with `fn foo` in the value namespace.
#[proc_macro_attribute]
pub fn remote(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);

    let (attrs, vis, sig, block) = (&input.attrs, &input.vis, &input.sig, &input.block);

    if !sig.generics.params.is_empty() {
        return compile_err(
            syn::spanned::Spanned::span(&sig.generics),
            "`#[cindy::remote]` functions cannot be generic",
        );
    }

    let function_ident = &sig.ident;
    let asyncness = &sig.asyncness;
    let inputs = &sig.inputs;
    let return_type = match &sig.output {
        syn::ReturnType::Default => quote! { () },
        syn::ReturnType::Type(_, ty) => quote! { #ty },
    };

    let mut arg_idents = vec![];
    let mut arg_types = vec![];
    for input_arg in &sig.inputs {
        match input_arg {
            FnArg::Receiver(r) => {
                return compile_err(
                    syn::spanned::Spanned::span(r),
                    "`#[cindy::remote]` functions cannot take `self`",
                );
            }
            FnArg::Typed(pat_type) => match &*pat_type.pat {
                Pat::Ident(PatIdent { ident, .. }) => {
                    if let Some(why) = check_remote_arg(&pat_type.ty) {
                        return compile_err(syn::spanned::Spanned::span(&pat_type.ty), why);
                    }
                    arg_idents.push(ident);
                    arg_types.push(&pat_type.ty)
                }
                other => {
                    return compile_err(
                        syn::spanned::Spanned::span(other),
                        "only plain named arguments are supported (no patterns)",
                    );
                }
            },
        }
    }

    let invocation = if asyncness.is_some() {
        quote! { #function_ident::inner( #(#arg_idents),* ).await }
    } else {
        quote! {
            match cindy::__reexports::tokio::task::spawn_blocking(move || {
                #function_ident::inner( #(#arg_idents),* )
            })
            .await
            {
                Ok(v) => v,
                Err(je) => ::std::panic::resume_unwind(je.into_panic()),
            }
        }
    };

    let outer_docstring = format!(
        "This function can be called from the orchestrator.

To run the remote-side version of this function (e.g. to call it from another remote function),
see [`{function_ident}::inner`]."
    );
    let inner_docstring = format!(
        "This function can be called from another remote functions.

For documentation about the actual function, please refer to [`{function_ident}`]."
    );
    quote! {
        #[allow(non_camel_case_types)]
        #[doc(hidden)]
        #vis enum #function_ident {}

        #[doc(hidden)]
        impl #function_ident {
            /// Stable identity of this remote function on the RPC wire.
            /// `module_path!` makes it unique per item (two same-named
            /// fns in different modules of one file can't collide) and
            /// expands identically in the orchestrator and worker
            /// builds, which compile the same source.
            #[doc(hidden)]
            pub const __CINDY_REMOTE_ID: &'static str =
                ::core::concat!(::core::module_path!(), "::", ::core::stringify!(#function_ident));

            #[doc = #inner_docstring]
            #(#attrs)*
            pub #asyncness fn inner (#inputs) -> #return_type #block
        }

        #[cfg(feature = "orchestrator")]
        #[doc = #outer_docstring]
        #(#attrs)*
        #vis fn #function_ident (#inputs) -> impl ::std::future::Future<Output = #return_type> {
            cindy::orchestrator::call(
                #function_ident::__CINDY_REMOTE_ID,
                cindy::__reexports::postcard::to_allocvec(&( #(#arg_idents),* ))
                    .expect("Failed to serialize args"),
            )
        }

        #[cfg(feature = "remote")]
        cindy::__reexports::inventory::submit! {
            cindy::remote::RemoteFn {
                id: #function_ident::__CINDY_REMOTE_ID,
                function: |args_bytes| {
                    let ( #(#arg_idents),* ): ( #(#arg_types),* ) =
                        cindy::__reexports::postcard::from_bytes(&args_bytes)
                        .expect("Failed to deserialize args");

                    ::std::boxed::Box::pin(async move {
                        let result = #invocation;
                        cindy::__reexports::postcard::to_allocvec(&result)
                            .expect("Failed to serialize return value")
                    })
                },
            }
        }
    }
    .into()
}

/// Defines a builtin "action": one author-written function with ergonomic
/// `impl Into<T>` arguments and a real body, from which the macro generates
/// both the wire-level `#[remote]` entry point *and* the ergonomic layer.
///
/// `#[remote]` requires concrete, postcard-serializable argument types (no
/// generics), but call sites want `impl Into<T>` so they can pass `&str`,
/// literals, etc. Those can't be one function, so historically each action
/// was two hand-written items: a concrete `*_raw` `#[remote]` fn plus a
/// body-less convenience shim. `#[action]` collapses that to one: you write
/// the `impl Into` fn with its body once, and the macro emits:
///
/// 1. **`<name>_raw(<concrete args>)`** — a `#[remote]` fn whose body is
///    *your* body (the `impl Into<T>` params rewritten to their concrete `T`).
///    This is the real, registered remote entry point.
/// 2. **`<name>(<impl Into args>)`** (orchestrator) — converts each arg with
///    `.into()` and `.await`s the `<name>_raw` RPC shim (runs on the worker).
/// 3. **`<name>::inner(<impl Into args>)`** (both features) — converts and
///    calls `<name>_raw::inner(..)` directly, in-process (no RPC).
///
/// Asyncness is taken from the annotated fn — async fns produce an async
/// `_raw`/`::inner` (the body is `.await`-capable); no marker needed.
///
/// ```ignore
/// #[crate::action]
/// pub async fn restart(name: impl Into<String>) -> crate::Result<super::Return> {
///     apply(State { name, runtime: Some(RuntimeAction::Restarted), ..Default::default() }).await
/// }
/// ```
#[proc_macro_attribute]
pub fn action(_args: TokenStream, input: TokenStream) -> TokenStream {
    let func = parse_macro_input!(input as ItemFn);
    let (attrs, vis, sig, block) = (&func.attrs, &func.vis, &func.sig, &func.block);

    if !sig.generics.params.is_empty() {
        return compile_err(
            syn::spanned::Spanned::span(&sig.generics),
            "`#[action]` functions cannot have generic parameters (use `impl Into<T>` args)",
        );
    }

    let ident = &sig.ident;
    let raw_ident = format_ident!("{ident}_raw");
    let is_async = sig.asyncness.is_some();
    let (maybe_async, maybe_await) = if is_async {
        (quote! { async }, quote! { .await })
    } else {
        (quote! {}, quote! {})
    };
    let return_type = match &sig.output {
        syn::ReturnType::Default => quote! { () },
        syn::ReturnType::Type(_, ty) => quote! { #ty },
    };

    // Build, in lockstep:
    //  - `ergonomic_inputs`: the original `impl Into<T>` params (the shim sig),
    //  - `raw_inputs`: the same params with each `impl Into<T>` lowered to `T`
    //    (the concrete `#[remote]` sig),
    //  - `arg_idents`: param names, forwarded as `ident.into()` from the shims.
    let mut ergonomic_inputs = vec![];
    let mut raw_inputs = vec![];
    let mut arg_idents = vec![];
    for input_arg in &sig.inputs {
        let FnArg::Typed(pat_type) = input_arg else {
            return compile_err(
                syn::spanned::Spanned::span(input_arg),
                "`#[action]` functions cannot take `self`",
            );
        };
        let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat else {
            return compile_err(
                syn::spanned::Spanned::span(&pat_type.pat),
                "only plain named arguments are supported in `#[action]` fns",
            );
        };
        arg_idents.push(ident.clone());
        ergonomic_inputs.push(input_arg.clone());

        // `impl Into<T>` lowers to `T` for the wire-level `#[remote]`
        // fn; any *other* `impl Trait` can't cross the wire and would
        // otherwise surface as an inscrutable error inside generated
        // code — reject it here with a span.
        let concrete_ty = match into_target(&pat_type.ty) {
            Some(t) => t,
            None if matches!(&*pat_type.ty, syn::Type::ImplTrait(_)) => {
                return compile_err(
                    syn::spanned::Spanned::span(&pat_type.ty),
                    "`impl Into<T>` is the only impl-trait argument `#[action]` supports",
                );
            }
            None => (*pat_type.ty).clone(),
        };
        raw_inputs.push(quote! { #ident: #concrete_ty });
    }

    quote! {
        // (1) The real, wire-level entry point: a `#[remote]` fn with concrete
        // args, carrying the author's body verbatim.
        #[doc(hidden)]
        #[cindy::remote]
        #vis #maybe_async fn #raw_ident (#(#raw_inputs),*) -> #return_type #block

        // (2) Orchestrator shim: convert args, drive the remote worker.
        #[cfg(feature = "orchestrator")]
        #(#attrs)*
        #vis async fn #ident (#(#ergonomic_inputs),*) -> #return_type {
            #raw_ident ( #(#arg_idents.into()),* ).await
        }

        // (3) Local/in-process variant (`#ident::inner`), under BOTH features:
        // worker builtins call siblings with it, and orchestrator code uses it
        // to act on the *local* machine without RPC. Lives in the type
        // namespace so it coexists with the `fn #ident` shim.
        #[allow(non_camel_case_types)]
        #vis enum #ident {}

        impl #ident {
            #(#attrs)*
            #vis #maybe_async fn inner (#(#ergonomic_inputs),*) -> #return_type {
                #raw_ident ::inner( #(#arg_idents.into()),* ) #maybe_await
            }
        }
    }
    .into()
}
