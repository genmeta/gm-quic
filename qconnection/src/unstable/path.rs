use dashmap::DashMap;
use deref_derive::{Deref, DerefMut};

pub use crate::path::{Path, Pathway};

#[derive(Default, Deref, DerefMut)]
pub struct Paths(DashMap<Pathway, Path>);
