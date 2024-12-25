use core::{
    pin::Pin,
    task::{Context, Poll},
};
use std::{ops::Deref, sync::Arc};

pub trait Publish<Key> {
    type Resource;

    fn subscribe(&self, key: &Key);

    fn unsubscribe(&self, key: &Key);

    fn poll_acquire(&self, cx: &mut Context, key: &Key) -> Poll<Option<Self::Resource>>;

    fn subscription(&self, key: Key) -> Subscription<Self, Key>
    where
        Self: Clone,
    {
        self.subscribe(&key);
        Subscription {
            subscribe: key,
            publisher: self.clone(),
        }
    }
}

impl<P: Publish<Key>, Key> Publish<Key> for Arc<P> {
    type Resource = P::Resource;

    #[inline]
    fn subscribe(&self, key: &Key) {
        self.deref().subscribe(key);
    }

    #[inline]
    fn poll_acquire(&self, cx: &mut Context, key: &Key) -> Poll<Option<Self::Resource>> {
        self.deref().poll_acquire(cx, key)
    }

    #[inline]
    fn unsubscribe(&self, key: &Key) {
        self.deref().unsubscribe(key);
    }
}

pub struct Subscription<P: Publish<Key>, Key> {
    subscribe: Key,
    publisher: P,
}

impl<Key, P: Publish<Key>> futures::Stream for Subscription<P, Key> {
    type Item = P::Resource;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.publisher.poll_acquire(cx, &self.subscribe)
    }
}

impl<Key, P: Publish<Key>> Drop for Subscription<P, Key> {
    fn drop(&mut self) {
        self.publisher.unsubscribe(&self.subscribe);
    }
}

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
