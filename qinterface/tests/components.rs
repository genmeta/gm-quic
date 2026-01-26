mod common;

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use common::*;
use qinterface::{Interface, component::Component, manager::InterfaceManager};

#[derive(Debug, Default)]
struct RouterState {
    shutdown_calls: AtomicUsize,
    reinit_calls: AtomicUsize,
}

#[derive(Debug, Clone)]
struct RouterComponent {
    state: Arc<RouterState>,
}

impl Component for RouterComponent {
    fn poll_shutdown(&self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        self.state.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        std::task::Poll::Ready(())
    }

    fn reinit(&self, _iface: &Interface) {
        self.state.reinit_calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Default)]
struct ClientState {
    saw_router: AtomicBool,
    missing_router_reinits: AtomicUsize,
}

#[derive(Debug, Clone)]
struct ClientComponent {
    state: Arc<ClientState>,
}

impl Component for ClientComponent {
    fn poll_shutdown(&self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        std::task::Poll::Ready(())
    }

    fn reinit(&self, iface: &Interface) {
        let has_router = iface
            .with_components(|cs| cs.get::<RouterComponent>().is_some())
            .expect("reinit should always see a non-stale iface");

        if has_router {
            self.state.saw_router.store(true, Ordering::SeqCst);
        } else {
            self.state
                .missing_router_reinits
                .fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[test]
fn component_dependency_missing_then_added_is_observable_on_rebind() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());

        let bind_uri = test_bind_uri();
        let bind_iface = manager.bind(bind_uri, factory).await;

        let client_state = Arc::new(ClientState::default());
        bind_iface.insert_component_with(|_iface| ClientComponent {
            state: client_state.clone(),
        });

        // First rebind: client exists, router missing
        bind_iface.rebind().await;
        assert!(!client_state.saw_router.load(Ordering::SeqCst));
        assert!(client_state.missing_router_reinits.load(Ordering::SeqCst) > 0);

        // Add dependency later, then rebind again: client should observe it.
        let router_state = Arc::new(RouterState::default());
        bind_iface.insert_component_with(|_iface| RouterComponent {
            state: router_state.clone(),
        });

        bind_iface.rebind().await;
        assert!(client_state.saw_router.load(Ordering::SeqCst));
        assert!(router_state.reinit_calls.load(Ordering::SeqCst) > 0);
    })
}

#[test]
fn component_dependency_present_is_visible_inside_reinit() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());

        let bind_uri = test_bind_uri();
        let bind_iface = manager.bind(bind_uri, factory).await;

        let router_state = Arc::new(RouterState::default());
        bind_iface.insert_component_with(|_iface| RouterComponent {
            state: router_state.clone(),
        });

        let client_state = Arc::new(ClientState::default());
        bind_iface.insert_component_with(|_iface| ClientComponent {
            state: client_state.clone(),
        });

        bind_iface.rebind().await;
        assert!(client_state.saw_router.load(Ordering::SeqCst));
        assert!(router_state.reinit_calls.load(Ordering::SeqCst) > 0);
    })
}
