mod common;

use std::{sync::Arc, time::Duration};

use common::*;
use qinterface::{
    component::location::{AddressEvent, Locations, LocationsComponent},
    manager::InterfaceManager,
};
use tokio::time;

#[test]
fn locations_component_emits_closed_then_upsert_on_rebind() {
    run(async {
        let manager = InterfaceManager::global().clone();
        let factory = Arc::new(FakeFactory::new());

        let bind_uri = test_bind_uri();
        let bind_iface = manager.bind(bind_uri.clone(), factory).await;

        let locations = Arc::new(Locations::new());
        let mut observer = locations.subscribe();

        bind_iface.insert_component_with(|iface| {
            LocationsComponent::new(iface.downgrade(), locations.clone())
        });

        // initial upsert (real_addr result) should be delivered to the subscriber
        let (u_bind, ev) = time::timeout(Duration::from_secs(2), observer.recv())
            .await
            .expect("timeout waiting for initial upsert")
            .expect("observer closed");
        assert_eq!(u_bind, bind_uri);
        assert!(matches!(ev, AddressEvent::Upsert(_)));

        // trigger rebind
        bind_iface.rebind().await;

        // must see Closed then Upsert for same bind_uri
        let (c_bind, c_ev) = time::timeout(Duration::from_secs(2), observer.recv())
            .await
            .expect("timeout waiting for closed")
            .expect("observer closed");
        assert_eq!(c_bind, bind_uri);
        assert!(matches!(c_ev, AddressEvent::Closed));

        let (u2_bind, u2_ev) = time::timeout(Duration::from_secs(2), observer.recv())
            .await
            .expect("timeout waiting for upsert")
            .expect("observer closed");
        assert_eq!(u2_bind, bind_uri);
        assert!(matches!(u2_ev, AddressEvent::Upsert(_)));

        // sanity: stale interface should not be able to touch component
        let old_iface = bind_iface.borrow();
        bind_iface.rebind().await;
        let err = old_iface.with_components(|_c| ()).unwrap_err();
        let _ = err;
    })
}
