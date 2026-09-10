use proc_macro::TokenStream;

use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, GenericParam, Ident, ItemFn, Token};

#[proc_macro_attribute]
pub fn platform_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let cases = parse_macro_input!(attr with Punctuated::<Ident, Token![,]>::parse_terminated);
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
    if cases.is_empty() {
        return syn::Error::new_spanned(&test.sig, "select at least one platform")
            .into_compile_error()
            .into();
    }

    let name = &test.sig.ident;
    let output = &test.sig.output;
    let tests = cases.iter().map(|case| {
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
                super::#name::<crate::platform::#platform>()
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
