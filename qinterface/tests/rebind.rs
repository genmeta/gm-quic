mod common;

use std::{io::ErrorKind, sync::Arc};

use common::*;
use qinterface::{RebindedError, io::IO, manager::InterfaceManager};

#[test]
fn manual_rebind_makes_old_interface_stale() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());

        let bind_uri = test_bind_uri();
        let bind_iface = manager.bind(bind_uri.clone(), factory).await;

        let old_iface = bind_iface.borrow();

        // install a component so we can validate stale with_component
        let probe = Arc::new(Probe::default());
        bind_iface.insert_component_with(|_iface| ProbeComponent::new(probe.clone()));

        // rebind -> new bind_id
        bind_iface.rebind().await;
        let new_iface = bind_iface.borrow();
        assert!(!old_iface.same_io(&new_iface));

        // Old iface IO operations should fail with ConnectionReset/RebindedError
        let err = old_iface.bound_addr().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionReset);
        assert!(RebindedError::is_source_of(err.get_ref().unwrap()));

        // Old iface component access should fail with RebindedError
        let err = old_iface
            .with_component::<ProbeComponent, _>(|_c| ())
            .unwrap_err();
        let _ = err; // it's exactly RebindedError

        // New iface works
        new_iface.bound_addr().expect("new iface should be usable");
        assert!(probe.reinit_calls.load(std::sync::atomic::Ordering::SeqCst) > 0);
    })
}
