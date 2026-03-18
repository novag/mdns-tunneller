pub fn get_filter_domains() -> Vec<String> {
    vec![
        "_matter._tcp.local".into(),
        "_matterc._udp.local".into(),
        "_meshcop._udp.local".into(),
    ]
}
