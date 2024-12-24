pub trait Subscribe<Res> {
    type Error;
    fn deliver(&self, res: Res) -> Result<(), Self::Error>;
}

impl<F, E, Res> Subscribe<Res> for F
where
    F: Fn(Res) -> Result<(), E>,
{
    type Error = E;

    #[inline]
    fn deliver(&self, res: Res) -> Result<(), Self::Error> {
        (self)(res)
    }
}
