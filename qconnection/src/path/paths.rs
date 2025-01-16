use std::sync::Arc;

use dashmap::DashMap;
use deref_derive::{Deref, DerefMut};
use qinterface::path::Pathway;
use tokio::task::AbortHandle;

use super::Path;

#[derive(Deref)]
pub struct PathContext {
    #[deref]
    path: Arc<Path>,
    task: AbortHandle,
}

impl Drop for PathContext {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl PathContext {
    pub fn new(path: Arc<Path>, task: AbortHandle) -> Self {
        Self { path, task }
    }
}

#[derive(Default, Deref, DerefMut)]
pub struct Paths(DashMap<Pathway, PathContext>);

impl Paths {
    pub fn new() -> Self {
        Self::default()
    }
}
