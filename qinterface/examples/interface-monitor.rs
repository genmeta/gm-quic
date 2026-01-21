use qinterface::device::Devices;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let global = Devices::global();
    let mut monitor = global.monitor();
    for (name, iface) in monitor.interfaces() {
        println!("Interface: {name} => {iface:#?}");
    }
    while let Some((_devices, event)) = monitor.update().await {
        println!("Event: {event:#?}");
    }
}
