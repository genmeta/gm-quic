use qbase::packet::PacketWriter;
use qrecovery::reliable::SendGuard;

pub struct Transaction<'b, H, S> {
    header: H,
    writer: PacketWriter<'b>,
    // 不同空间的send guard类型不一样
    journal: SendGuard<'b, S>,
}
