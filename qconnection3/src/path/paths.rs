use std::sync::Arc;

use dashmap::DashMap;

#[derive(Default)]
pub struct Paths(DashMap<super::Pathway, Arc<super::Path>>);

impl Paths {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_with(&self, pathway: super::Pathway, new_path: impl FnOnce() -> Arc<super::Path>) {
        self.0.entry(pathway).or_insert_with(new_path);
    }

    pub fn del(&self, pathway: &super::Pathway) {
        self.0.remove(pathway);
    }

    pub fn get(&self, pathway: &super::Pathway) -> Option<Arc<super::Path>> {
        self.0.get(pathway).map(|arc| arc.value().clone())
    }
}
