mod common;

use std::{io::ErrorKind, sync::Arc, time::Duration};

use common::*;
use qinterface::{io::IO, manager::InterfaceManager};
use tokio::time;

#[test]
fn unbind_destroys_and_weak_upgrade_fails() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());
        let state = factory.state.clone();

        let bind_uri = test_bind_uri();
        let bind_iface: qinterface::BindInterface = manager.bind(bind_uri.clone(), factory).await;
        let weak_bind = bind_iface.downgrade();
        let weak_iface = bind_iface.borrow_weak();

        // unbind is async; ensure it completes
        manager.unbind(bind_uri.clone()).await;

        // existing strong handle remains upgradeable, but should be unusable
        let err = bind_iface.borrow().real_addr().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotConnected);

        // ensure IO was actually closed
        time::timeout(Duration::from_secs(2), async {
            while state.close_calls.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("unbind did not close IO in time");

        drop(bind_iface);

        time::timeout(Duration::from_secs(2), async {
            loop {
                if weak_bind.upgrade().is_err() && weak_iface.upgrade().is_err() {
                    break;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("weak upgrade should eventually fail after unbind + drop");
    })
}

#[test]
fn auto_drop_when_last_ref_gone_allows_rebind() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());
        let state = factory.state.clone();

        let bind_uri = test_bind_uri();

        // Bind and create a borrowed Interface (strong ref)
        let bind_iface: qinterface::BindInterface =
            manager.bind(bind_uri.clone(), factory.clone()).await;
        let iface = bind_iface.borrow();
        drop(bind_iface);
        drop(iface);

        // Binding again must wait for the dropped signal, so this also verifies auto-drop.
        let _bind_iface2 = time::timeout(Duration::from_secs(2), async {
            manager.bind(bind_uri.clone(), factory.clone()).await
        })
        .await
        .expect("rebind after auto-drop timed out");

        assert!(state.close_calls.load(std::sync::atomic::Ordering::SeqCst) > 0);
    })
}
