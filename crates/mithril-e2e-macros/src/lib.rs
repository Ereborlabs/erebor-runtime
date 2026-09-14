use proc_macro::TokenStream;

use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, GenericParam, Ident, ItemFn, Token};

struct PlatformArgs {
    cases: Vec<Ident>,
    shared: bool,
}

impl Parse for PlatformArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut cases = Vec::new();
        let mut scope = None;
        while !input.is_empty() {
            let name = input.parse::<Ident>()?;
            if input.peek(Token![=]) {
                input.parse::<Token![=]>()?;
                let value = input.parse::<Ident>()?;
                if name != "scope" || scope.is_some() {
                    return Err(syn::Error::new_spanned(name, "unknown or duplicate option"));
                }
                scope = Some(match value.to_string().as_str() {
                    "shared" => true,
                    "isolated" => false,
                    _ => {
                        return Err(syn::Error::new_spanned(
                            value,
                            "scope must be shared or isolated",
                        ))
                    }
                });
            } else {
                cases.push(name);
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(Self {
            cases,
            shared: scope.unwrap_or(true),
        })
    }
}

#[proc_macro_attribute]
pub fn platform_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as PlatformArgs);
    let test = parse_macro_input!(item as ItemFn);

    if test.sig.asyncness.is_some() {
        return syn::Error::new_spanned(
            &test.sig,
            "the platform fixture must own the async runtime",
        )
        .into_compile_error()
        .into();
    }
    if !test.sig.inputs.is_empty()
        || test.sig.generics.params.len() != 1
        || !matches!(
            test.sig.generics.params.first(),
            Some(GenericParam::Type(_))
        )
    {
        return syn::Error::new_spanned(
            &test.sig,
            "a platform test must have one platform type parameter and no arguments",
        )
        .into_compile_error()
        .into();
    }
    if args.cases.is_empty() {
        return syn::Error::new_spanned(&test.sig, "select at least one platform")
            .into_compile_error()
            .into();
    }

    let name = &test.sig.ident;
    let output = &test.sig.output;
    let shared = args.shared;
    let tests = args.cases.iter().map(|case| {
        let value = case.to_string();
        let platform = match value.as_str() {
            "host" => format_ident!("Host"),
            "runc" => format_ident!("Runc"),
            "kubernetes" => format_ident!("Kubernetes"),
            _ => return syn::Error::new_spanned(case, "unknown platform").into_compile_error(),
        };
        quote! {
            #[test]
            #[ignore = "requires its physical test environment"]
            fn #case() #output {
                super::#name::<crate::platform::#platform<#shared>>()
            }
        }
    });

    quote! {
        #test

        #[cfg(test)]
        mod #name {
            use super::*;

            #(#tests)*
        }
    }
    .into()
}
