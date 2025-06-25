use proc_macro::TokenStream;
use syn::Error;

mod derive;

#[proc_macro_derive(ParameterId, attributes(param))]
pub fn quic_parameters(item: TokenStream) -> TokenStream {
    TokenStream::from(derive::quic_parameters(item).unwrap_or_else(Error::into_compile_error))
}
