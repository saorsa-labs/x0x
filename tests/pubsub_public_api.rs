//! Compile witnesses for the supported standalone pub/sub surface.

use x0x::error::NetworkResult;
use x0x::gossip::{GossipConfig, PubSubManager};

/// WHY: standalone consumers construct `PubSubManager` directly. This test is
/// outside the library crate, so it stops compiling if limiter configuration
/// accidentally becomes crate-private again. It opens no socket and runs no
/// async work.
#[test]
fn standalone_manager_can_access_egress_configuration() {
    async fn configure(manager: &mut PubSubManager, config: &GossipConfig) -> NetworkResult<()> {
        manager.configure_egress(config).await
    }

    std::hint::black_box(configure);
}
