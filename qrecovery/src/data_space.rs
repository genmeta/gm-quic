use std::collections::HashMap;

use qbase::streamid::StreamId;

pub struct DataSpace {
    senders: HashMap<StreamId, u64>,
}
