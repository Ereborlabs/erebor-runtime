use proc_macro::TokenStream;

use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, Expr, GenericParam, Ident, ItemFn, Meta, Token};

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
    let mut lifecycle = None;
    test.attrs.retain(|attr| {
        if !attr.path().is_ident("lifecycle") {
            return true;
        }
        if lifecycle.is_some() {
            lifecycle = Some(Err(syn::Error::new_spanned(attr, "duplicate lifecycle")));
            return false;
        }
        lifecycle = Some(match &attr.meta {
            Meta::NameValue(value) => match &value.value {
                Expr::Path(value) => value
                    .path
                    .get_ident()
                    .cloned()
                    .ok_or_else(|| syn::Error::new_spanned(attr, "lifecycle must be one name")),
                _ => Err(syn::Error::new_spanned(attr, "lifecycle must be one name")),
            },
            _ => Err(syn::Error::new_spanned(attr, "lifecycle must be one name")),
        });
        false
    });
    let (lifecycle, lifecycle_name) = match lifecycle {
        Some(Ok(lifecycle)) => (quote!(stringify!(#lifecycle)), Some(lifecycle)),
        Some(Err(error)) => return error.into_compile_error().into(),
        None => (
            quote!(concat!(module_path!(), "::", stringify!(#name))),
            None,
        ),
    };
    let tests = args.cases.iter().map(|case| {
        let value = case.to_string();
        let case_name = match &lifecycle_name {
            Some(lifecycle) => format_ident!("{lifecycle}_{case}"),
            None => format_ident!("{name}_{case}"),
        };
        let platform = match value.as_str() {
            "host" => format_ident!("Host"),
            "runc" => format_ident!("Runc"),
            "kubernetes" => format_ident!("Kubernetes"),
            _ => return syn::Error::new_spanned(case, "unknown platform").into_compile_error(),
        };
        quote! {
            #[test]
            #[ignore = "requires its physical test environment"]
            fn #case_name() #output {
                crate::platform::test_lifecycle::<crate::platform::#platform, _>(#lifecycle, || {
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
