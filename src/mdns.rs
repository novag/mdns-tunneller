use dns_parser::Packet as mDNSPacket;
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::{
    datalink::{self, Channel::Ethernet, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        udp::UdpPacket,
        Packet,
    },
};
use std::collections::{HashSet, VecDeque};
use std::fmt::Write;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};

const IPV6_HDRINCL: libc::c_int = 36;

// IPv6 minimum MTU (1280) minus IPv6 header (40) minus Fragment Extension Header (8).
// Rounded down to multiple of 8 as required by IPv6 fragmentation.
// Used as a conservative fallback when we get EMSGSIZE.
const FALLBACK_IPV6_FRAG_PAYLOAD: usize = (1280 - 40 - 8) & !7; // 1232

static FRAG_ID: AtomicU32 = AtomicU32::new(1);

type RecentPackets = Arc<Mutex<VecDeque<u64>>>;
type TrackedHostnames = Arc<Mutex<HashSet<String>>>;

enum DnsPayload<'a> {
    V4(&'a [u8]),
    V6(&'a [u8]),
}

// Extract the DNS payload from a raw Ethernet frame containing an mDNS packet.
fn extract_dns_payload(packet: &[u8]) -> Option<DnsPayload<'_>> {
    let eth = EthernetPacket::new(packet)?;
    let eth_hdr = eth.packet().len() - eth.payload().len();

    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(eth.payload())?;
            if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                return None;
            }
            let ipv4_hdr = ipv4.packet().len() - ipv4.payload().len();
            let udp = UdpPacket::new(ipv4.payload())?;
            if udp.get_destination() != 5353 {
                return None;
            }
            let udp_hdr = udp.packet().len() - udp.payload().len();
            let offset = eth_hdr + ipv4_hdr + udp_hdr;
            Some(DnsPayload::V4(&packet[offset..offset + udp.payload().len()]))
        }
        EtherTypes::Ipv6 => {
            let ipv6 = Ipv6Packet::new(eth.payload())?;
            if ipv6.get_next_header() != IpNextHeaderProtocols::Udp {
                return None;
            }
            let ipv6_hdr = ipv6.packet().len() - ipv6.payload().len();
            let udp = UdpPacket::new(ipv6.payload())?;
            if udp.get_destination() != 5353 {
                return None;
            }
            let udp_hdr = udp.packet().len() - udp.payload().len();
            let offset = eth_hdr + ipv6_hdr + udp_hdr;
            Some(DnsPayload::V6(&packet[offset..offset + udp.payload().len()]))
        }
        _ => None,
    }
}

// Strip the ethernet header, returning (is_ipv4, ip_packet_bytes).
fn extract_ip_packet(frame: &[u8]) -> Option<(bool, &[u8])> {
    let eth = EthernetPacket::new(frame)?;
    let hdr_len = eth.packet().len() - eth.payload().len();
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => Some((true, &frame[hdr_len..])),
        EtherTypes::Ipv6 => Some((false, &frame[hdr_len..])),
        _ => None,
    }
}

fn packet_hash(data: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // Hash only the DNS payload so the dedup works even if ethernet/IP headers
    // differ between the sent frame and the recaptured frame.
    if let Some(payload) = extract_dns_payload(data) {
        let bytes = match payload {
            DnsPayload::V4(b) => b,
            DnsPayload::V6(b) => b,
        };
        bytes.hash(&mut hasher);
    } else {
        data.hash(&mut hasher);
    }
    hasher.finish()
}

/// An mDNS listener on a specific interface.
#[allow(non_camel_case_types)]
pub struct mDNSListener {
    pub eth_rx: Box<dyn DataLinkReceiver>,
    // `EthernetPacket` with `mDNS`
    pub channel_tx: UnboundedSender<Vec<u8>>,
    pub filter_domains: Vec<String>,
    // Hashes of recently injected packets, used to skip recaptured self-injections.
    pub recently_sent: RecentPackets,
    // Hostnames learned from SRV records, so we also forward their A/AAAA records.
    pub tracked_hostnames: TrackedHostnames,
}

impl mDNSListener {
    /// Listen mDNS packet, than send `EthernetPacket` to channel
    pub fn listen(&mut self) {
        // mDNSPacket<'a>
        let mut mdns_buf = Vec::new();

        while let Ok(packet) = self.eth_rx.next() {
            // Skip packets we recently injected (raw injection is visible to our own capture).
            {
                let hash = packet_hash(packet);
                let mut recent = self.recently_sent.lock().unwrap();
                if let Some(pos) = recent.iter().position(|&h| h == hash) {
                    recent.remove(pos);
                    continue;
                }
            }

            if let Some(eth) = EthernetPacket::new(packet) {
                if let Some(mdns) = mdns_packet(&eth, &mut mdns_buf) {
                    let summary = describe_mdns(&mdns);
                    debug!(summary, "local: received mDNS from interface");
                    let domain_match = filter_packet(&mdns, &self.filter_domains);
                    let hostname_match = {
                        let hostnames = self.tracked_hostnames.lock().unwrap();
                        matches_tracked_hostname(&mdns, &hostnames)
                    };
                    if domain_match || hostname_match {
                        {
                            let mut hostnames = self.tracked_hostnames.lock().unwrap();
                            extract_srv_targets(&mdns, &mut hostnames);
                        }
                        info!(summary, "tunnel: forwarding mDNS to peer");
                        if self.channel_tx.send(packet.to_vec()).is_err() {
                            break;
                        }
                    }
                }
            };
        }
    }
}

/// An mDNS Sender on a specific interface.
#[allow(non_camel_case_types)]
pub struct mDNSSender {
    // Held to keep the datalink channel (and thus eth_rx) alive.
    _eth_tx: Box<dyn DataLinkSender>,
    // Raw IP sockets with IP_HDRINCL. Sends the full IP+UDP packet through
    // the kernel IP stack, preserving the original source IP:port so unicast
    // mDNS responses route back to the correct origin. This also delivers to
    // local multicast subscribers (unlike raw ethernet injection which
    // bypasses the kernel).
    pub raw4: socket2::Socket,
    pub raw6: socket2::Socket,
    pub iface_index: u32,
    // Shared with listener to skip recaptured self-injections.
    pub recently_sent: RecentPackets,
    // Shared with listener — hostnames learned from tunnelled SRV records.
    pub tracked_hostnames: TrackedHostnames,
}

impl mDNSSender {
    /// packet is a `EthernetPacket` with `mDNS`
    pub fn send(&mut self, packet: &[u8]) -> Option<Result<(), io::Error>> {
        let mut mdns_buf = Vec::new();
        if let Some(eth) = EthernetPacket::new(packet) {
            if let Some(mdns) = mdns_packet(&eth, &mut mdns_buf) {
                let summary = describe_mdns(&mdns);
                info!(summary, "local: sending mDNS to interface");
                let mut hostnames = self.tracked_hostnames.lock().unwrap();
                extract_srv_targets(&mdns, &mut hostnames);
            }
        }
        // Record hash BEFORE sending so the listener thread doesn't
        // capture and re-forward the injected packet.
        {
            let hash = packet_hash(packet);
            let mut recent = self.recently_sent.lock().unwrap();
            if recent.len() >= 64 {
                recent.pop_front();
            }
            recent.push_back(hash);
        }
        let result = if let Some((is_v4, ip_packet)) = extract_ip_packet(packet) {
            if is_v4 {
                let dest: socket2::SockAddr =
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353))
                        .into();
                self.raw4.send_to(ip_packet, &dest)
                    .map(|_| ())
                    .map_err(io::Error::from)
            } else {
                let dest: socket2::SockAddr = SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb),
                    0,
                    0,
                    self.iface_index,
                ))
                .into();
                match self.raw6.send_to(ip_packet, &dest) {
                    Ok(_) => Ok(()),
                    Err(e) if e.raw_os_error() == Some(libc::EMSGSIZE) => {
                        if let Some(fragments) = fragment_ipv6(ip_packet, FALLBACK_IPV6_FRAG_PAYLOAD) {
                            warn!(
                                original_size = ip_packet.len(),
                                max_fragment_payload = FALLBACK_IPV6_FRAG_PAYLOAD,
                                count = fragments.len(),
                                "EMSGSIZE: fragmenting IPv6 packet"
                            );
                            let mut result = Ok(());
                            for frag in &fragments {
                                if let Err(e) = self.raw6.send_to(frag, &dest) {
                                    result = Err(io::Error::from(e));
                                    break;
                                }
                            }
                            result
                        } else {
                            Err(io::Error::from(e))
                        }
                    }
                    Err(e) => Err(io::Error::from(e)),
                }
            }
        } else {
            Ok(())
        };
        Some(result)
    }
}

pub fn pair(
    interface: &NetworkInterface,
    channel_tx: UnboundedSender<Vec<u8>>,
    filter_domains: Vec<String>,
) -> (mDNSSender, mDNSListener) {
    // Create a channel to receive on
    let (tx, rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("unable to create channel: {}", e),
    };

    let iface_ip = interface
        .ips
        .iter()
        .find_map(|ip| {
            if let IpAddr::V4(v4) = ip.ip() {
                Some(v4)
            } else {
                None
            }
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    let raw4 = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
    )
    .expect("raw4 socket (needs CAP_NET_RAW)");
    raw4.set_multicast_if_v4(&iface_ip)
        .expect("set_multicast_if_v4");
    raw4.set_multicast_loop_v4(true)
        .expect("set_multicast_loop_v4");
    raw4.set_multicast_ttl_v4(1)
        .expect("set_multicast_ttl_v4");

    let raw6 = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(libc::IPPROTO_UDP)),
    )
    .expect("raw6 socket (needs CAP_NET_RAW)");
    unsafe {
        let optval: libc::c_int = 1;
        let ret = libc::setsockopt(
            raw6.as_raw_fd(),
            libc::IPPROTO_IPV6,
            IPV6_HDRINCL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        assert!(ret == 0, "failed to set IPV6_HDRINCL");
    }
    raw6.set_multicast_if_v6(interface.index)
        .expect("set_multicast_if_v6");
    raw6.set_multicast_loop_v6(true)
        .expect("set_multicast_loop_v6");
    raw6.set_multicast_hops_v6(1)
        .expect("set_multicast_hops_v6");

    let recently_sent: RecentPackets = Arc::new(Mutex::new(VecDeque::new()));
    let tracked_hostnames: TrackedHostnames = Arc::new(Mutex::new(HashSet::new()));

    (
        mDNSSender {
            _eth_tx: tx,
            raw4,
            raw6,
            iface_index: interface.index,
            recently_sent: recently_sent.clone(),
            tracked_hostnames: tracked_hostnames.clone(),
        },
        mDNSListener {
            eth_rx: rx,
            channel_tx,
            filter_domains,
            recently_sent,
            tracked_hostnames,
        },
    )
}

/// get multicast dns packet
fn mdns_packet<'a>(ethernet: &EthernetPacket, buf: &'a mut Vec<u8>) -> Option<mDNSPacket<'a>> {
    fn ipv4_packet(payload: &[u8]) -> Option<Ipv4Packet> {
        let packet = Ipv4Packet::new(payload)?;
        if !packet.get_destination().is_multicast()
            || !matches!(packet.get_next_level_protocol(), IpNextHeaderProtocols::Udp)
        {
            return None;
        }
        Some(packet)
    }

    fn ipv6_packet(payload: &[u8]) -> Option<Ipv6Packet> {
        let packet = Ipv6Packet::new(payload)?;
        if !packet.get_destination().is_multicast()
            || !matches!(packet.get_next_header(), IpNextHeaderProtocols::Udp)
        {
            return None;
        }
        Some(packet)
    }

    fn udp_packet(payload: &[u8]) -> Option<UdpPacket> {
        UdpPacket::new(payload)
    }

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet = ipv4_packet(ethernet.payload())?;
            let udp_packet = udp_packet(ipv4_packet.payload())?;
            *buf = udp_packet.payload().to_vec();
            mDNSPacket::parse(buf).ok()
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet = ipv6_packet(ethernet.payload())?;
            let udp_packet = udp_packet(ipv6_packet.payload())?;
            *buf = udp_packet.payload().to_vec();
            mDNSPacket::parse(buf).ok()
        }
        _ => None,
    }
}

fn rdata_type(data: &dns_parser::RData) -> &'static str {
    match data {
        dns_parser::RData::A(_) => "A",
        dns_parser::RData::AAAA(_) => "AAAA",
        dns_parser::RData::CNAME(_) => "CNAME",
        dns_parser::RData::PTR(_) => "PTR",
        dns_parser::RData::NS(_) => "NS",
        dns_parser::RData::MX(_) => "MX",
        dns_parser::RData::SRV(_) => "SRV",
        dns_parser::RData::SOA(_) => "SOA",
        dns_parser::RData::TXT(_) => "TXT",
        dns_parser::RData::Unknown(_) => "Unknown",
    }
}

fn describe_mdns(packet: &mDNSPacket) -> String {
    let mut desc = String::new();
    for q in &packet.questions {
        let _ = write!(desc, "query({} {:?}) ", q.qname, q.qtype);
    }
    let names: Vec<String> = packet
        .answers
        .iter()
        .map(|a| format!("{} {}", a.name, rdata_type(&a.data)))
        .collect();
    if !names.is_empty() {
        let _ = write!(desc, "{} answers: {}", names.len(), names.join(", "));
    }
    desc.trim_end().to_string()
}

/// Describe an mDNS packet from raw ethernet frame bytes, for logging.
pub fn describe_raw(raw: &[u8]) -> Option<String> {
    let mut buf = Vec::new();
    let eth = EthernetPacket::new(raw)?;
    let mdns = mdns_packet(&eth, &mut buf)?;
    Some(describe_mdns(&mdns))
}

// Extract SRV target hostnames from all sections of an mDNS packet.
fn extract_srv_targets(packet: &mDNSPacket, hostnames: &mut HashSet<String>) {
    for record in packet
        .answers
        .iter()
        .chain(packet.additional.iter())
    {
        if let dns_parser::RData::SRV(ref srv) = record.data {
            let target = srv.target.to_string();
            if hostnames.insert(target.clone()) {
                info!(target, "tracking hostname from SRV record");
            }
        }
    }
}

// Check if any question or answer in the packet matches a tracked hostname.
fn matches_tracked_hostname(packet: &mDNSPacket, hostnames: &HashSet<String>) -> bool {
    if hostnames.is_empty() {
        return false;
    }
    let check = |name: &str| hostnames.contains(name);
    packet
        .questions
        .iter()
        .any(|q| check(&q.qname.to_string()))
        || packet
            .answers
            .iter()
            .any(|a| check(&a.name.to_string()))
}

// Fragment an IPv6 packet using the given max fragment payload size.
// The payload size must be a multiple of 8.
fn fragment_ipv6(ip_packet: &[u8], max_frag_payload: usize) -> Option<Vec<Vec<u8>>> {
    const IPV6_HDR: usize = 40;
    const FRAG_HDR: usize = 8;

    if ip_packet.len() < IPV6_HDR {
        return None;
    }

    let max_payload = max_frag_payload & !7; // ensure multiple of 8
    let original_next_header = ip_packet[6];
    let payload = &ip_packet[IPV6_HDR..];
    let ident = FRAG_ID.fetch_add(1, Ordering::Relaxed);

    let mut fragments = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let remaining = payload.len() - offset;
        let chunk = if remaining > max_payload {
            max_payload
        } else {
            remaining
        };
        let more = offset + chunk < payload.len();

        let mut frag = Vec::with_capacity(IPV6_HDR + FRAG_HDR + chunk);

        // IPv6 header — copy and patch next_header + payload_length
        frag.extend_from_slice(&ip_packet[..IPV6_HDR]);
        frag[6] = 44; // Next Header = Fragment (44)
        let payload_len = (FRAG_HDR + chunk) as u16;
        frag[4] = (payload_len >> 8) as u8;
        frag[5] = payload_len as u8;

        // Fragment Extension Header (8 bytes)
        frag.push(original_next_header); // Next Header (e.g. UDP=17)
        frag.push(0); // Reserved
        let frag_off_field = ((offset as u16 / 8) << 3) | if more { 1 } else { 0 };
        frag.push((frag_off_field >> 8) as u8);
        frag.push(frag_off_field as u8);
        frag.extend_from_slice(&ident.to_be_bytes());

        // Fragment data
        frag.extend_from_slice(&payload[offset..offset + chunk]);

        fragments.push(frag);
        offset += chunk;
    }

    Some(fragments)
}

fn filter_packet(packet: &mDNSPacket, domains: &[String]) -> bool {
    let matches_domain = |name: &str| {
        domains.iter().any(|d| name == d || name.ends_with(&format!(".{}", d)))
    };

    let question_matched = packet
        .questions
        .iter()
        .any(|record| matches_domain(&record.qname.to_string()));

    let answer_matched = packet
        .answers
        .iter()
        .any(|record| matches_domain(&record.name.to_string()));

    question_matched || answer_matched
}
