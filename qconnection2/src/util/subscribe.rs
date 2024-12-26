use core::{
    pin::Pin,
    task::{Context, Poll},
};
use std::{ops::Deref, sync::Arc};

pub(crate) trait Publish<Key: Copy> {
    type Resource;

    type Subscription: futures::Stream<Item = Self::Resource>;

    fn subscribe(&self, key: Key) -> Self::Subscription;

    fn unsubscribe(&self, key: &Key);

    fn resources_viewer(&self, key: Key) -> ResourceViewer<Self, Key>
    where
        Self: Clone,
    {
        ResourceViewer {
            subscribe: key,
            subscription: self.subscribe(key),
            publisher: self.clone(),
        }
    }
}

impl<P: Publish<Key>, Key: Copy> Publish<Key> for Arc<P> {
    type Resource = P::Resource;
    type Subscription = P::Subscription;

    #[inline]
    fn subscribe(&self, key: Key) -> Self::Subscription {
        self.deref().subscribe(key)
    }

    #[inline]
    fn unsubscribe(&self, key: &Key) {
        self.deref().unsubscribe(key);
    }
}

#[derive(Clone)]
pub(crate) struct ResourceViewer<P: Publish<Key>, Key: Copy> {
    subscribe: Key,
    publisher: P,
    subscription: P::Subscription,
}

impl<P: Publish<Key>, Key: Copy> ResourceViewer<P, Key> {
    pub fn into_lease(self) -> ResourceLease<P, Key> {
        ResourceLease {
            subscribe: self.subscribe,
            publisher: self.publisher,
            subscription: self.subscription,
        }
    }
}

impl<Key: Copy, P: Publish<Key>> futures::Stream for ResourceViewer<P, Key>
where
    P: Unpin,
    Key: Unpin,
    P::Subscription: Unpin,
{
    type Item = P::Resource;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        core::pin::Pin::new(&mut self.get_mut().subscription).poll_next(cx)
    }
}

pub(crate) struct ResourceLease<P: Publish<Key>, Key: Copy> {
    subscribe: Key,
    publisher: P,
    subscription: P::Subscription,
}

impl<Key: Copy, P: Publish<Key>> futures::Stream for ResourceLease<P, Key>
where
    P: Unpin,
    Key: Unpin,
    P::Subscription: Unpin,
{
    type Item = P::Resource;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        core::pin::Pin::new(&mut self.get_mut().subscription).poll_next(cx)
    }
}

impl<Key: Copy, P: Publish<Key>> Drop for ResourceLease<P, Key> {
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
