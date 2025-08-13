use crate::test_harness::common::all_online;
use commonware_macros::test_traced;
use commonware_p2p::simulated::{self, Link, Network, Oracle, Receiver, Sender};

#[test]
fn test_basic() {
    assert!(true);
}

#[test_traced]
fn test_20_blocks_and_verify() {
    let link = Link {
        latency: 80.0,
        jitter: 10.0,
        success_rate: 0.98,
    };
    all_online(10, 0, link.clone(), 20, true);
}
