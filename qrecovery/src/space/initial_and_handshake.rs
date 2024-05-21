use crate::{crypto::CryptoStream, streams::NoStreams};
use deref_derive::{Deref, DerefMut};

#[derive(Debug, Deref, DerefMut)]
pub struct InitialSpace(#[deref] super::ArcSpace<CryptoStream, NoStreams>);
#[derive(Debug, Deref, DerefMut)]
pub struct HandshakeSpace(#[deref] super::ArcSpace<CryptoStream, NoStreams>);
