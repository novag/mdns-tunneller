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
use std::fmt::Write;
use std::io;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info};

/// An mDNS listener on a specific interface.
#[allow(non_camel_case_types)]
pub struct mDNSListener {
    pub eth_rx: Box<dyn DataLinkReceiver>,
    // `EthernetPacket` with `mDNS`
    pub channel_tx: UnboundedSender<Vec<u8>>,
    pub filter_domains: Vec<String>,
}

impl mDNSListener {
    /// Listen mDNS packet, than send `EthernetPacket` to channel
    pub fn listen(&mut self) {
        // mDNSPacket<'a>
        let mut mdns_buf = Vec::new();

        while let Ok(packet) = self.eth_rx.next() {
            if let Some(eth) = EthernetPacket::new(packet) {
                if let Some(mdns) = mdns_packet(&eth, &mut mdns_buf) {
                    let summary = describe_mdns(&mdns);
                    debug!(summary, "local: received mDNS from interface");
                    if filter_packet(&mdns, &self.filter_domains) {
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
    pub eth_tx: Box<dyn DataLinkSender>,
}

impl mDNSSender {
    /// packet is a `EthernetPacket` with `mDNS`
    pub fn send(&mut self, packet: &[u8]) -> Option<Result<(), io::Error>> {
        let mut mdns_buf = Vec::new();
        if let Some(eth) = EthernetPacket::new(packet) {
            if let Some(mdns) = mdns_packet(&eth, &mut mdns_buf) {
                let summary = describe_mdns(&mdns);
                info!(summary, "local: sending mDNS to interface");
            }
        }
        self.eth_tx.send_to(packet, None)
    }
}

pub fn pair(
    interface: &NetworkInterface,
    channel_tx: UnboundedSender<Vec<u8>>,
    filter_domains: Vec<String>,
) -> (mDNSSender, mDNSListener) {
    // Create a channel to receive on
    let (tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type"),
        Err(e) => panic!("unable to create channel: {}", e),
    };
    (
        mDNSSender { eth_tx: tx },
        mDNSListener {
            eth_rx: rx,
            channel_tx,
            filter_domains,
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

fn filter_packet(packet: &mDNSPacket, domains: &[String]) -> bool {
    let question_matched = packet
        .questions
        .iter()
        .any(|record| domains.contains(&record.qname.to_string()));

    let answer_matched = packet
        .answers
        .iter()
        .any(|record| domains.contains(&record.name.to_string()));

    question_matched || answer_matched
}
