use std::collections::HashMap;

use crate::streamid::StreamId;

pub struct DataSpace {
    senders: HashMap<StreamId, u64>,
}
