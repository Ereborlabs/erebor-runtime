use proc_macro::TokenStream;

use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, Expr, GenericParam, Ident, ItemFn, Lit, Meta, Token};

struct PlatformArgs {
    cases: Vec<Ident>,
}

impl Parse for PlatformArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut cases = Vec::new();
        while !input.is_empty() {
            cases.push(input.parse::<Ident>()?);
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(Self { cases })
    }
}

#[proc_macro_attribute]
pub fn platform_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as PlatformArgs);
    let mut test = parse_macro_input!(item as ItemFn);

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
    let mut scope = None;
    test.attrs.retain(|attr| {
        if !attr.path().is_ident("scope") {
            return true;
        }
        if scope.is_some() {
            scope = Some(Err(syn::Error::new_spanned(attr, "duplicate scope")));
            return false;
        }
        scope = Some(match &attr.meta {
            Meta::NameValue(value) => match &value.value {
                Expr::Lit(value) => match &value.lit {
                    Lit::Str(value) if !value.value().is_empty() => Ok(value.clone()),
                    _ => Err(syn::Error::new_spanned(attr, "scope must be a string")),
                },
                _ => Err(syn::Error::new_spanned(attr, "scope must be a string")),
            },
            _ => Err(syn::Error::new_spanned(attr, "scope must be a string")),
        });
        false
    });
    let scope = match scope {
        Some(Ok(scope)) => quote!(#scope),
        Some(Err(error)) => return error.into_compile_error().into(),
        None => quote!(concat!(module_path!(), "::", stringify!(#name))),
    };
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
                crate::platform::test_scope::<crate::platform::#platform, _>(#scope, || {
                    super::#name::<crate::platform::#platform>()
                })
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
