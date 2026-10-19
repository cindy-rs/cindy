use proc_macro::TokenStream;
use proc_macro2::TokenStream as Tokens;
use quote::{format_ident, quote};
use syn::{FnArg, Item, ItemFn, Pat, PatIdent, ReturnType};

fn expand<T: syn::parse::Parse>(
    input: TokenStream,
    f: impl FnOnce(T) -> syn::Result<Tokens>,
) -> TokenStream {
    syn::parse(input)
        .and_then(f)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn error<T>(spanned: impl quote::ToTokens, msg: &str) -> syn::Result<T> {
    Err(syn::Error::new_spanned(spanned, msg))
}

/// How generated code names cindy: `crate` inside cindy itself, else
/// whatever the invoking crate calls the dependency — an attribute
/// macro can't see the path it was invoked by, so a hardcoded
/// `::cindy` would break renamed dependencies.
struct Cindy {
    /// `crate` or `::name`; `::crate` isn't a path.
    path: Tokens,
    /// The same, for `#[serde(crate = "…")]`.
    path_str: String,
}

/// Not cached here: proc-macro-crate caches per manifest, and a cache
/// of ours would be wrong in rust-analyzer's one long-lived process
/// expanding many crates.
fn cindy() -> syn::Result<Cindy> {
    use proc_macro_crate::{FoundCrate, crate_name};
    let name = match crate_name("cindy") {
        Ok(FoundCrate::Itself) => None,
        Ok(FoundCrate::Name(name)) => Some(name),
        Err(e) => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                format!(
                    "couldn't resolve the `cindy` crate for generated code ({e}); \
                     is `cindy` a dependency of this crate?"
                ),
            ));
        }
    };
    Ok(match name {
        None => Cindy {
            path: quote! { crate },
            path_str: "crate".to_owned(),
        },
        Some(name) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            Cindy {
                path: quote! { ::#ident },
                path_str: format!("::{name}"),
            }
        }
    })
}

fn return_type(sig: &syn::Signature) -> Tokens {
    match &sig.output {
        ReturnType::Default => quote! { () },
        ReturnType::Type(_, ty) => quote! { #ty },
    }
}

/// `impl Into<T>` → `Some(T)`.
fn into_target(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::ImplTrait(it) = ty else {
        return None;
    };
    it.bounds.iter().find_map(|bound| {
        let syn::TypeParamBound::Trait(tb) = bound else {
            return None;
        };
        let seg = tb.path.segments.last()?;
        let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
            return None;
        };
        match args.args.first() {
            Some(syn::GenericArgument::Type(inner)) if seg.ident == "Into" => Some(inner.clone()),
            _ => None,
        }
    })
}

/// A sync body runs in `spawn_blocking`, re-raising its panic.
fn call_body(c: &Tokens, asyncness: bool, call: Tokens) -> Tokens {
    if asyncness {
        quote! { #call.await }
    } else {
        quote! {
            match #c::__reexports::tokio::task::spawn_blocking(move || #call).await {
                Ok(v) => v,
                Err(je) => ::std::panic::resume_unwind(je.into_panic()),
            }
        }
    }
}

/// The package's own library, when `#[cindy::main]` is expanding in
/// another of its targets (normally the bin).
///
/// Worker registrations (`#[cindy::remote]` fns, `secret!` demands)
/// are link-time `inventory` statics. The worker build compiles none of
/// the user's `main` body, so nothing in it names the lib, and rustc
/// leaves an unreferenced crate out of the link — taking every
/// registration in it along. An `extern crate` forces the link, and the
/// lib's name has to come from the manifest: nothing else tells a proc
/// macro which crates exist.
fn playbook_lib() -> Option<syn::Ident> {
    let env = |key| std::env::var(key).ok();
    let dir = std::path::PathBuf::from(env("CARGO_MANIFEST_DIR")?);
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).ok()?;
    let name = linkable_lib(&manifest, dir.join("src/lib.rs").is_file())?;

    // Expanding inside the lib itself: a bin target sets
    // `CARGO_BIN_NAME` even when it shares the lib's crate name.
    if env("CARGO_BIN_NAME").is_none() && env("CARGO_CRATE_NAME").as_deref() == Some(&name) {
        return None;
    }
    syn::parse_str(&name).ok()
}

/// The crate name of the manifest's library target, if it has one a
/// bin can `extern crate` — the same rules cargo applies: an explicit
/// `[lib]` (unless it's a proc-macro or has no rlib-ish crate type),
/// else `src/lib.rs` unless `autolib = false`.
fn linkable_lib(manifest: &str, has_src_lib_rs: bool) -> Option<String> {
    let manifest = manifest.parse::<toml_edit::DocumentMut>().ok()?;
    let package = manifest.get("package")?.as_table_like()?;

    let name = match manifest.get("lib").and_then(|lib| lib.as_table_like()) {
        Some(lib) => {
            let get = |key: &str| lib.get(key).or_else(|| lib.get(&key.replace('-', "_")));
            if get("proc-macro").and_then(|v| v.as_bool()) == Some(true) {
                return None;
            }
            if let Some(types) = get("crate-type").and_then(|v| v.as_array())
                && !types
                    .iter()
                    .any(|t| matches!(t.as_str(), Some("lib" | "rlib" | "dylib")))
            {
                return None;
            }
            lib.get("name").and_then(|v| v.as_str()).map(str::to_owned)
        }
        None => {
            let autolib = package.get("autolib").and_then(|v| v.as_bool());
            if autolib == Some(false) || !has_src_lib_rs {
                return None;
            }
            None
        }
    };
    Some(match name {
        Some(name) => name,
        None => package.get("name")?.as_str()?.replace('-', "_"),
    })
}

/// Derive `Debug`, `Serialize` and `Deserialize` without a `serde`
/// dependency. (`Debug` is what `cindy inventory` renders vars with;
/// don't derive it again.)
#[proc_macro_attribute]
pub fn wire(_args: TokenStream, input: TokenStream) -> TokenStream {
    expand(input, |item: Item| {
        if !matches!(item, Item::Enum(_) | Item::Struct(_) | Item::Union(_)) {
            return error(
                &item,
                "`#[cindy::wire]` can only be applied to structs, enums, and unions",
            );
        }
        let Cindy { path: c, path_str } = cindy()?;
        let serde_crate = format!("{path_str}::__reexports::serde");
        Ok(quote! {
            #[derive(
                ::std::fmt::Debug,
                #c::__reexports::serde::Serialize,
                #c::__reexports::serde::Deserialize
            )]
            #[serde(crate = #serde_crate)]
            #item
        })
    })
}

/// The playbook's entry point. Built with `orchestrator`, it is the
/// program; built with `remote`, the body is dropped and the binary
/// serves RPC.
///
/// `main` returns a `Result` and takes nothing, or the target's
/// `cindy::Host<V>` (`Host<()>` for just `name` and `tags`). `async` is
/// optional: the body always runs in an async context.
///
/// A library in the same package is linked into both builds, so its
/// `#[cindy::remote]` fns and `secret!`s reach the worker.
#[proc_macro_attribute]
pub fn main(_args: TokenStream, input: TokenStream) -> TokenStream {
    expand(input, |input: ItemFn| {
        let (attrs, vis, sig, block) = (&input.attrs, &input.vis, &input.sig, &input.block);
        let (output, inputs) = (&sig.output, &sig.inputs);

        let returns_result = matches!(output, ReturnType::Type(_, ty)
            if matches!(&**ty, syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Result")));
        if !returns_result {
            return error(
                output,
                "`#[cindy::main]` must return a `Result` (e.g. `-> cindy::Result<()>`): \
                 the generated wrapper matches on `Ok`/`Err` to pick the process exit code",
            );
        }
        if let Some(c) = &sig.constness {
            return error(c, "`#[cindy::main]` functions cannot be `const`");
        }
        if let Some(u) = &sig.unsafety {
            return error(u, "`#[cindy::main]` functions cannot be `unsafe`");
        }
        if let Some(abi) = &sig.abi {
            return error(
                abi,
                "`#[cindy::main]` functions cannot be declared with an ABI",
            );
        }
        if let Some(v) = &sig.variadic {
            return error(v, "`#[cindy::main]` functions cannot be variadic");
        }
        if !sig.generics.params.is_empty() {
            return error(
                &sig.generics,
                "`#[cindy::main]` functions cannot be generic",
            );
        }

        let Cindy { path: c, path_str } = cindy()?;
        let tokio_crate = format!("{path_str}::__reexports::tokio");
        let host = match inputs.iter().collect::<Vec<_>>().as_slice() {
            [] => quote! {},
            // The host type comes from `__user_main`'s signature.
            [FnArg::Typed(_)] => quote! { #c::entry::host_context() },
            [FnArg::Receiver(r)] => return error(r, "`#[cindy::main]` cannot take `self`"),
            _ => {
                return error(
                    inputs,
                    "`#[cindy::main]` accepts at most one parameter (the host context, `cindy::Host<V>`)",
                );
            }
        };
        // `as _`, so a playbook's own `extern crate <lib>;` doesn't collide.
        let link_lib = playbook_lib().map(|lib| quote! { extern crate #lib as _; });

        Ok(quote! {
            #link_lib

            #(#attrs)*
            #[#c::__reexports::tokio::main(crate = #tokio_crate)]
            #vis async fn main() {
                // Without either feature, `main` would be a silent no-op.
                #[cfg(not(any(feature = "orchestrator", feature = "remote")))]
                ::core::compile_error!(
                    "a cindy binary must be built with the `orchestrator` or `remote` feature \
                     (add `default = [\"orchestrator\", \"remote\"]` to [features] for plain \
                     `cargo check`)"
                );

                #[allow(unused_variables)]
                let (rpc_in, rpc_out) = #c::common::quarantine_stdio();

                #[cfg(all(feature = "remote", not(feature = "orchestrator")))]
                {
                    #c::remote::rpc(rpc_in, rpc_out).await;
                    ::std::process::exit(0);
                }

                // Positive cfg, so both features at once (rust-analyzer)
                // still analyse the body.
                #[cfg(feature = "orchestrator")]
                {
                    async fn __user_main(#inputs) #output #block

                    #c::entry::orchestrator_init(rpc_in, rpc_out).await;
                    match #c::__reexports::tokio::spawn(__user_main(#host)).await {
                        ::std::result::Result::Ok(::std::result::Result::Ok(_)) => ::std::process::exit(0),
                        ::std::result::Result::Ok(::std::result::Result::Err(e)) => {
                            ::std::eprintln!("\x1b[31m{:?}\x1b[0m", e);
                            ::std::process::exit(1);
                        }
                        ::std::result::Result::Err(_) => ::std::process::exit(1),
                    }
                }
            }
        })
    })
}

/// The inventory: exactly one per binary, any name, sync or async,
/// returning `cindy::Inventory<V>` or a `Result` of one.
///
/// ```rust,ignore
/// #[cindy::wire]
/// struct Vars { region: String }
///
/// #[cindy::inventory]
/// fn inventory() -> cindy::Inventory<Vars> {
///     cindy::Inventory::new([
///         cindy::Host::new("web-01", ["env:prod", "web"], Vars { region: "eu".into() }),
///     ])
/// }
/// ```
#[proc_macro_attribute]
pub fn inventory(_args: TokenStream, input: TokenStream) -> TokenStream {
    expand(input, |input: ItemFn| {
        let (attrs, vis, sig, block) = (&input.attrs, &input.vis, &input.sig, &input.block);
        let (ident, asyncness, output) = (&sig.ident, &sig.asyncness, &sig.output);
        if !sig.inputs.is_empty() {
            return error(
                &sig.inputs,
                "`#[cindy::inventory]` functions must take no arguments",
            );
        }
        let c = cindy()?.path;
        let invocation = call_body(&c, asyncness.is_some(), quote! { #ident() });
        Ok(quote! {
            #(#attrs)*
            #vis #asyncness fn #ident () #output #block

            #c::__reexports::inventory::submit! {
                #c::inventory::RegisteredInventory {
                    dump: || ::std::boxed::Box::pin(async move {
                        #c::inventory::IntoInventoryDump::into_inventory_dump(#invocation)
                    }),
                }
            }
        })
    })
}

/// A function that runs on the target. `foo(args)` becomes an RPC shim
/// (orchestrator builds) returning a future that is dispatched eagerly;
/// the body itself is `foo::inner(args)`, for calling from other remote
/// code without a round trip (an uninhabited `enum foo` gives the path
/// a type-namespace home next to `fn foo`).
///
/// Arguments and the return value must be `Serialize + Deserialize`,
/// except that in a returned `cindy::Result<T>` only `T` must be: the
/// error crosses with its whole chain (see `cindy::error`).
#[proc_macro_attribute]
pub fn remote(_args: TokenStream, input: TokenStream) -> TokenStream {
    expand(input, |input: ItemFn| {
        let (attrs, vis, sig, block) = (&input.attrs, &input.vis, &input.sig, &input.block);
        if !sig.generics.params.is_empty() {
            return error(
                &sig.generics,
                "`#[cindy::remote]` functions cannot be generic",
            );
        }
        let c = cindy()?.path;
        let (ident, asyncness, inputs) = (&sig.ident, &sig.asyncness, &sig.inputs);
        let return_type = return_type(sig);

        let mut arg_idents = vec![];
        let mut arg_types = vec![];
        for arg in inputs {
            let FnArg::Typed(pat_type) = arg else {
                return error(arg, "`#[cindy::remote]` functions cannot take `self`");
            };
            let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat else {
                return error(
                    &pat_type.pat,
                    "only plain named arguments are supported (no patterns)",
                );
            };
            match &*pat_type.ty {
                syn::Type::ImplTrait(_) => {
                    return error(
                        &pat_type.ty,
                        "`impl Trait` arguments are not allowed in `#[cindy::remote]` fns — use a \
                     concrete type (`#[cindy::action]` supports `impl Into<T>`)",
                    );
                }
                syn::Type::Reference(_) => {
                    return error(
                        &pat_type.ty,
                        "reference arguments are not allowed in `#[cindy::remote]` fns — arguments \
                     cross the wire and must be owned (e.g. `String` instead of `&str`)",
                    );
                }
                _ => {}
            }
            arg_idents.push(ident);
            arg_types.push(&pat_type.ty);
        }
        let invocation = call_body(
            &c,
            asyncness.is_some(),
            quote! { #ident::inner( #(#arg_idents),* ) },
        );
        let outer_doc = format!(
            "Runs on the target. To run the body in-process (from other remote code), \
             see [`{ident}::inner`]."
        );
        let inner_doc = format!("The body of [`{ident}`], run in-process.");

        Ok(quote! {
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            #vis enum #ident {}

            #[doc(hidden)]
            impl #ident {
                // `module_path!` keeps same-named fns in different modules
                // apart, and expands alike in both builds.
                #[doc(hidden)]
                pub const __CINDY_REMOTE_ID: &'static str =
                    ::core::concat!(::core::module_path!(), "::", ::core::stringify!(#ident));

                #[doc = #inner_doc]
                #(#attrs)*
                pub #asyncness fn inner (#inputs) -> #return_type #block
            }

            #[cfg(feature = "orchestrator")]
            #[doc = #outer_doc]
            #(#attrs)*
            #vis fn #ident (#inputs) -> impl ::std::future::Future<Output = #return_type> {
                let response = #c::orchestrator::call(
                    #ident::__CINDY_REMOTE_ID,
                    #c::__reexports::postcard::to_allocvec(&( #(#arg_idents),* ))
                        .expect("Failed to serialize args"),
                );
                async move {
                    use #c::error::wire::{ViaSerde as _, ViaWireError as _};
                    let bytes = response.await;
                    (&#c::error::wire::Return::<#return_type>::new())
                        .decode(&bytes)
                        .unwrap_or_else(|e| ::std::panic!(
                            "failed to deserialize return value of `{}`: {e:?}",
                            #ident::__CINDY_REMOTE_ID,
                        ))
                }
            }

            #[cfg(feature = "remote")]
            #c::__reexports::inventory::submit! {
                #c::remote::RemoteFn {
                    id: #ident::__CINDY_REMOTE_ID,
                    function: |args_bytes| {
                        let ( #(#arg_idents),* ): ( #(#arg_types),* ) =
                            #c::__reexports::postcard::from_bytes(&args_bytes)
                            .expect("Failed to deserialize args");
                        ::std::boxed::Box::pin(async move {
                            use #c::error::wire::{ViaSerde as _, ViaWireError as _};
                            let result = #invocation;
                            (&#c::error::wire::Return::<#return_type>::new())
                                .encode(result)
                                .expect("Failed to serialize return value")
                        })
                    },
                }
            }
        })
    })
}

/// A builtin with `impl Into<T>` arguments. `#[remote]` needs concrete
/// argument types, so from one fn this generates:
///
/// - `<name>_raw` — the `#[remote]` fn, `impl Into<T>` lowered to `T`,
///   carrying the body;
/// - `<name>(..)` — the orchestrator shim: `.into()` each argument,
///   await `<name>_raw`;
/// - `<name>::inner(..)` — the same, in-process.
///
/// The body must call plain helpers, not other remote fns.
///
/// ```ignore
/// #[crate::action]
/// pub async fn restart(name: impl Into<String>) -> crate::Result<super::Return> {
///     apply(intent(name, None, Some(RuntimeAction::Restarted))).await
/// }
/// ```
#[proc_macro_attribute]
pub fn action(_args: TokenStream, input: TokenStream) -> TokenStream {
    expand(input, |func: ItemFn| {
        let (attrs, vis, sig, block) = (&func.attrs, &func.vis, &func.sig, &func.block);
        if !sig.generics.params.is_empty() {
            return error(
                &sig.generics,
                "`#[action]` functions cannot have generic parameters (use `impl Into<T>` args)",
            );
        }
        let c = cindy()?.path;
        let ident = &sig.ident;
        let raw_ident = format_ident!("{ident}_raw");
        let (maybe_async, maybe_await) = if sig.asyncness.is_some() {
            (quote! { async }, quote! { .await })
        } else {
            (quote! {}, quote! {})
        };
        let return_type = return_type(sig);

        let inputs: Vec<&FnArg> = sig.inputs.iter().collect();
        let mut raw_inputs = vec![];
        let mut arg_idents = vec![];
        for arg in &inputs {
            let FnArg::Typed(pat_type) = arg else {
                return error(arg, "`#[action]` functions cannot take `self`");
            };
            let Pat::Ident(PatIdent { ident, .. }) = &*pat_type.pat else {
                return error(
                    &pat_type.pat,
                    "only plain named arguments are supported in `#[action]` fns",
                );
            };
            let concrete = match into_target(&pat_type.ty) {
                Some(t) => t,
                None if matches!(&*pat_type.ty, syn::Type::ImplTrait(_)) => {
                    return error(
                        &pat_type.ty,
                        "`impl Into<T>` is the only impl-trait argument `#[action]` supports",
                    );
                }
                None => (*pat_type.ty).clone(),
            };
            raw_inputs.push(quote! { #ident: #concrete });
            arg_idents.push(ident.clone());
        }

        Ok(quote! {
            #[doc(hidden)]
            #[#c::remote]
            #vis #maybe_async fn #raw_ident (#(#raw_inputs),*) -> #return_type #block

            #[cfg(feature = "orchestrator")]
            #(#attrs)*
            #vis async fn #ident (#(#inputs),*) -> #return_type {
                #raw_ident ( #(#arg_idents.into()),* ).await
            }

            // Both builds: worker code calls siblings with it, and the
            // orchestrator uses it to act on its own machine.
            #[allow(non_camel_case_types)]
            #vis enum #ident {}

            impl #ident {
                #(#attrs)*
                #vis #maybe_async fn inner (#(#inputs),*) -> #return_type {
                    #raw_ident ::inner( #(#arg_idents.into()),* ) #maybe_await
                }
            }
        })
    })
}

/// A file mode, checked at compile time: `cindy::mode!(0o644)`.
///
/// The literal must be octal — `mode!(644)` is refused, since decimal
/// 644 is a valid but unintended mode (`0o1204`) no range check could
/// catch. For a mode only known at runtime, use `Mode::try_from`.
#[proc_macro]
pub fn mode(input: TokenStream) -> TokenStream {
    expand(input, |lit: syn::LitInt| {
        let bits = octal_mode(&lit.to_string(), lit.suffix())
            .map_err(|msg| syn::Error::new_spanned(&lit, msg))?;
        let c = cindy()?.path;
        Ok(quote! { #c::builtin::path::Mode::__checked(#bits) })
    })
}

/// The bits of a mode literal as written (`0o644`, `0o6_44`, `0o644u32`).
fn octal_mode(text: &str, suffix: &str) -> Result<u32, String> {
    let digits = text.strip_suffix(suffix).unwrap_or(text);
    let Some(octal) = digits.strip_prefix("0o") else {
        return Err(format!(
            "file modes are octal: write `0o{digits}` (decimal {digits} is a different mode)"
        ));
    };
    let bits = u32::from_str_radix(&octal.replace('_', ""), 8)
        .map_err(|e| format!("invalid octal mode `{text}`: {e}"))?;
    if bits > 0o7777 {
        return Err(format!("mode `{text}` has bits outside 0o7777"));
    }
    Ok(bits)
}

#[cfg(test)]
mod tests {
    use super::{linkable_lib, octal_mode};

    #[test]
    fn mode_literals_must_be_octal_and_in_range() {
        assert_eq!(octal_mode("0o644", ""), Ok(0o644));
        assert_eq!(octal_mode("0o4_755", ""), Ok(0o4755));
        assert_eq!(octal_mode("0o600u32", "u32"), Ok(0o600));

        let decimal = octal_mode("644", "").unwrap_err();
        assert!(decimal.contains("`0o644`"), "{decimal}");
        assert!(octal_mode("0x1a4", "").is_err());
        assert!(octal_mode("0b110", "").is_err());
        let range = octal_mode("0o17777", "").unwrap_err();
        assert!(
            range.contains("0o7777") && !range.contains("decimal"),
            "{range}"
        );
    }

    const PACKAGE: &str = "[package]\nname = \"home-infra\"\n";

    #[test]
    fn implicit_lib_takes_the_package_name_with_underscores() {
        assert_eq!(linkable_lib(PACKAGE, true).as_deref(), Some("home_infra"));
    }

    #[test]
    fn no_lib_rs_means_no_lib() {
        assert_eq!(linkable_lib(PACKAGE, false), None);
    }

    #[test]
    fn autolib_false_ignores_lib_rs() {
        let manifest = format!("{PACKAGE}autolib = false\n");
        assert_eq!(linkable_lib(&manifest, true), None);
    }

    #[test]
    fn explicit_lib_section_wins_and_needs_no_lib_rs() {
        let manifest = format!("{PACKAGE}[lib]\nname = \"infra\"\npath = \"src/infra.rs\"\n");
        assert_eq!(linkable_lib(&manifest, false).as_deref(), Some("infra"));
        let manifest = format!("{PACKAGE}[lib]\npath = \"src/infra.rs\"\n");
        assert_eq!(
            linkable_lib(&manifest, false).as_deref(),
            Some("home_infra")
        );
    }

    #[test]
    fn unlinkable_libs_are_skipped() {
        for lib in [
            "proc-macro = true",
            "proc_macro = true",
            "crate-type = [\"cdylib\"]",
            "crate_type = [\"staticlib\"]",
        ] {
            let manifest = format!("{PACKAGE}[lib]\n{lib}\n");
            assert_eq!(linkable_lib(&manifest, true), None, "{lib}");
        }
        let manifest = format!("{PACKAGE}[lib]\ncrate-type = [\"cdylib\", \"rlib\"]\n");
        assert_eq!(linkable_lib(&manifest, true).as_deref(), Some("home_infra"));
    }
}
