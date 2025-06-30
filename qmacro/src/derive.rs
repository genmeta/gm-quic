use darling::{FromMeta, ast::NestedMeta};
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, format_ident, quote};
use syn::{Error, Expr, ExprRange, Ident, ItemEnum, Token, Variant, punctuated::Punctuated};

pub fn quic_parameters(item: TokenStream) -> Result<TokenStream2, Error> {
    let r#enum = syn::parse::<ItemEnum>(item)?;
    let enum_name = &r#enum.ident;

    let mut try_from_varint_match_arms = quote! {};
    let mut into_varint_match_arms = quote! {};
    // TODO: validate
    let mut validate_match_arms = quote! {};
    let mut default_value_match_arms = quote! {};
    let mut value_type_match_arms = quote! {};

    for variant in &r#enum.variants {
        let discriminant = match variant.discriminant.as_ref() {
            Some((_eq, discriminant)) => discriminant,
            None => {
                return Err(Error::new_spanned(
                    variant,
                    "Each variant must have a discriminant, e.g., `= 0`",
                ));
            }
        };

        let ident = &variant.ident;
        try_from_varint_match_arms.extend(quote! {
            // u64 => Self
            #discriminant => #enum_name::#ident,
        });
        into_varint_match_arms.extend(quote! {
            // Self => u64
            #enum_name::#ident => #discriminant,
        });

        let param_args = parse_variant_attrs(variant)?;
        let validate =
            (param_args.gen_validate(ident)).map_err(|msg| Error::new_spanned(variant, msg))?;
        validate_match_arms.extend(quote! {
            #enum_name::#ident => { #validate }
        });

        let default_value = param_args.gen_default_value();
        default_value_match_arms.extend(quote! {
            #enum_name::#ident => { #default_value }
        });

        let value_type = param_args.gen_value_type();
        value_type_match_arms.extend(quote! {
            #enum_name::#ident => #value_type,
        });
    }

    Ok(quote! {
        // TODO: try from
        impl ::core::convert::TryFrom<VarInt> for #enum_name {
            type Error = VarInt;

            fn try_from(value: VarInt) -> Result<Self, Self::Error> {
                Ok(match value.into_inner() {
                    #try_from_varint_match_arms
                    unknown => return Err(value)
                })
            }
        }

        impl From<#enum_name> for VarInt {
            fn from(value: #enum_name) -> Self {
                VarInt::from_u64(match value {
                    #into_varint_match_arms
                }).expect("All variants should have a valid discriminant")
            }
        }

        impl #enum_name {
            pub fn validate(&self, value: &ParameterValue) -> Result<(), String> {
                match self {
                    #validate_match_arms
                }
                Ok(())
            }

            pub fn default_value(&self) -> Option<ParameterValue> {
                match self {
                    #default_value_match_arms
                }
            }

            pub fn value_type(&self) -> ParameterType {
                match self {
                    #value_type_match_arms
                }
            }
        }
    })
}

fn parse_variant_attrs(variant: &Variant) -> Result<ParamArgs, Error> {
    let param_attr = variant
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("param"))
        .ok_or_else(|| {
            Error::new_spanned(
                variant,
                "Each variant must have a `#[param(...)]` attribute",
            )
        })?;

    let param_metas = param_attr
        .parse_args_with(Punctuated::<NestedMeta, Token![,]>::parse_terminated)?
        .into_iter()
        .collect::<Vec<_>>();

    ParamArgs::from_list(&param_metas).map_err(|de| de.into())
}

#[derive(darling::FromMeta)]
struct ParamArgs {
    value_type: ParamType,
    #[darling(default)]
    default: Option<Expr>,
    #[darling(default)]
    bound: Option<ExprRange>,
}

impl ParamArgs {
    fn gen_validate(&self, id: &Ident) -> Result<TokenStream2, &'static str> {
        let Some(bound) = &self.bound else {
            return Ok(quote! {});
        };

        let value_type = format_ident!("{}", format!("{:?}", self.value_type));
        let mut convert_value = quote! {
            let ParameterValue::#value_type(value) = value else {
                return Err(format!("Parameter {} expect type {}, but got {:?}", stringify!(#id), stringify!(#value_type), value));
            };
        };

        convert_value.extend(match self.value_type {
            ParamType::VarInt => quote! { value.into_inner() },
            ParamType::Duration => quote! { value.as_millis() as u64 },
            _ => return Err("Bound is only applicable to VarInt or Duration types"),
        });

        let bound_string = bound.to_token_stream().to_string();
        Ok(quote! {
            let value = { #convert_value };
            if !(#bound).contains(&value) {
                return Err(format!("Parameter {} out of bounds {}: {:?}", stringify!(#id), #bound_string, value));
            }
        })
    }

    fn gen_default_value(&self) -> TokenStream2 {
        match &self.default {
            Some(default) => quote! { Some((#default).into()) },
            None => quote! { None },
        }
    }

    fn gen_value_type(&self) -> TokenStream2 {
        let value_type = format_ident!("{}", format!("{:?}", self.value_type));
        quote! { ParameterType::#value_type }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamType {
    VarInt,
    Boolean,
    Bytes,
    Duration,
    ResetToken,
    ConnectionId,
    PreferredAddress,
}

impl FromMeta for ParamType {
    fn from_string(lit: &str) -> ::darling::Result<Self> {
        match lit {
            "VarInt" => Ok(ParamType::VarInt),
            "Boolean" => Ok(ParamType::Boolean),
            "Bytes" => Ok(ParamType::Bytes),
            "Duration" => Ok(ParamType::Duration),
            "ResetToken" => Ok(ParamType::ResetToken),
            "ConnectionId" => Ok(ParamType::ConnectionId),
            "PreferredAddress" => Ok(ParamType::PreferredAddress),
            __other => Err(::darling::Error::unknown_value(__other)),
        }
    }

    fn from_expr(expr: &Expr) -> darling::Result<Self> {
        match *expr {
            Expr::Lit(ref lit) => Self::from_value(&lit.lit),
            Expr::Group(ref group) => {
                // syn may generate this invisible group delimiter when the input to the darling
                // proc macro (specifically, the attributes) are generated by a
                // macro_rules! (e.g. propagating a macro_rules!'s expr)
                // Since we want to basically ignore these invisible group delimiters,
                // we just propagate the call to the inner expression.
                Self::from_expr(&group.expr)
            }
            Expr::Path(ref path) => return Self::from_string(&path.to_token_stream().to_string()),
            _ => Err(darling::Error::unexpected_expr_type(expr)),
        }
        .map_err(|e| e.with_span(expr))
    }
}
