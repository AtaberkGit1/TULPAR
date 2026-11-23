//! YOLAÇ Network Engine: Socket protection, LeakGuard, DPI TCP Relay, and Userspace TUN Router.

pub mod captive_portal;
pub mod ipv6_probe;
pub mod leak_guard;
pub mod protect;
pub mod relay;
pub mod tun_engine;

pub use captive_portal::{
    is_captive_portal_probe_domain, is_local_lan_ip, CaptivePortalMonitor, CaptivePortalState,
};
pub use ipv6_probe::probe_ipv6_leak_mode;
pub use leak_guard::{Ipv6LeakMode, LeakDecision, LeakGuard};
pub use protect::{
    connect_protected_tcp, bind_protected_udp, NoopProtector, ProtectedDialer, SocketProtector,
};
pub use relay::{DpiTcpRelay, FlowOutcome, NoopStrategyAdvisor, StrategyAdvisor};
pub use tun_engine::{
    ChannelPacketDevice, MemoryProfile, PacketDevice, TunConfig, TunEngine,
};
