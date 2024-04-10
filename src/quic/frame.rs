use std::fmt;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Type(u64);

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Type").field(&self.0).finish()
    }
}
