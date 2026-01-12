use qinterface::physical::PhysicalInterfaces;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let global = PhysicalInterfaces::global();
    let mut monitor = global.monitor();
    while let Some((_devices, event)) = monitor.update().await {
        println!("Event: {event:#?}");
    }
}
