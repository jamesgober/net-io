//! A server behind a proxy that sends the PROXY protocol (HAProxy `send-proxy`
//! or `send-proxy-v2`, nginx `proxy_protocol on`): each connection is answered
//! with the client address net-io learned from the header.
//!
//! ```text
//! cargo run --example behind_proxy -- 127.0.0.1:7002 /tmp/net-io-proxy.sock
//! ```
//!
//! The TCP listener trusts the proxies in `NET_IO_TRUSTED` (CIDR blocks,
//! separated by commas; loopback when unset): a peer outside them is closed
//! before any byte is read. The optional Unix listener (second argument, Unix
//! only) trusts every peer that can open the socket file (mode 0660 here).
//! Both accept PROXY v1 and v2.

use net_io::{
    AllowAll, ListenerSpec, NetError, ProxyMode, ProxyVersions, ServerBuilder, TcpConnection,
    TrustedProxies,
};

fn answer(conn: &mut TcpConnection) -> Result<(), NetError> {
    let info = conn.info();
    let client = info
        .client_addr()
        .map_or_else(|| "unknown".to_string(), |a| a.to_string());
    let via = info
        .socket_peer()
        .map_or_else(|| "local".to_string(), |a| a.to_string());
    conn.send_all(format!("client={client} via={via}\n").as_bytes())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:7002".to_string());
    let unix_path = args.next();
    let trusted = match std::env::var("NET_IO_TRUSTED") {
        Ok(list) => TrustedProxies::parse(&list)?,
        Err(_) => TrustedProxies::loopback(),
    };
    let proxy = ProxyMode::Required {
        versions: ProxyVersions::Both,
    };
    #[cfg_attr(not(all(unix, feature = "local")), allow(unused_mut))]
    let mut builder = ServerBuilder::new()
        .listener(ListenerSpec::tcp(addr.as_str()).proxy(proxy))
        .trusted_proxies(trusted);
    #[cfg(all(unix, feature = "local"))]
    if let Some(path) = &unix_path {
        let options = net_io::LocalOptions::new().mode(0o660);
        builder = builder.listener(ListenerSpec::unix(path, options).proxy(proxy));
    }
    #[cfg(not(all(unix, feature = "local")))]
    if unix_path.is_some() {
        eprintln!("Unix listeners need Unix and the `local` feature; ignoring the path");
    }
    let server = builder.handler(answer).gate(AllowAll).build()?;
    server.open_door()?;
    for l in server.listeners() {
        println!("behind_proxy listening on {} (PROXY v1 and v2)", l.local);
    }
    let report = server.wait_for_stop();
    println!("stopped: {report:?}");
    Ok(())
}
