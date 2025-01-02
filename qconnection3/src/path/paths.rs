use std::sync::Arc;

use dashmap::DashMap;

#[derive(Default)]
pub struct Paths(DashMap<super::Pathway, Arc<super::Path>>);

impl Paths {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, pathway: super::Pathway, path: Arc<super::Path>) {
        self.0.insert(pathway, path);
    }

    pub fn get(&self, pathway: &super::Pathway) -> Option<Arc<super::Path>> {
        self.0.get(pathway).map(|arc| arc.value().clone())
    }
}
