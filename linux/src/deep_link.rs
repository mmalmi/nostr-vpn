#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeepLink {
    JoinRequest(String),
    #[cfg(debug_assertions)]
    Debug(DebugAction),
}

/// Deep links are untrusted (any webpage can fire the scheme): join
/// requests must wait for confirmation, debug links apply directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeepLinkRoute {
    ConfirmJoinRequest(String),
    #[cfg(debug_assertions)]
    Debug(DebugAction),
}

pub fn route(link: DeepLink) -> DeepLinkRoute {
    match link {
        DeepLink::JoinRequest(request) => DeepLinkRoute::ConfirmJoinRequest(request),
        #[cfg(debug_assertions)]
        DeepLink::Debug(action) => DeepLinkRoute::Debug(action),
    }
}

#[cfg(debug_assertions)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugAction {
    Tick,
    AcceptJoin {
        network_id: Option<String>,
        requester_npub: Option<String>,
    },
}

pub fn parse(raw: &str) -> Option<DeepLink> {
    let raw = raw.trim();
    if !raw.starts_with("nvpn://") {
        return None;
    }
    if raw
        .get(.."nvpn://join-request".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("nvpn://join-request"))
    {
        return Some(DeepLink::JoinRequest(raw.to_string()));
    }

    #[cfg(debug_assertions)]
    {
        parse_debug(raw)
    }

    #[cfg(not(debug_assertions))]
    {
        None
    }
}

#[cfg(debug_assertions)]
fn parse_debug(raw: &str) -> Option<DeepLink> {
    let without_scheme = &raw["nvpn://".len()..];
    let head = without_scheme
        .split(['?', '#'])
        .next()
        .unwrap_or(without_scheme);
    let mut parts = head.splitn(2, '/');
    let host = parts.next().unwrap_or_default();
    if !host.eq_ignore_ascii_case("debug") {
        return None;
    }

    let action = parts.next().unwrap_or_default().trim_matches('/');
    match action {
        "tick" => Some(DeepLink::Debug(DebugAction::Tick)),
        "accept-join" => Some(DeepLink::Debug(DebugAction::AcceptJoin {
            network_id: query_value(raw, &["networkId", "network"]),
            requester_npub: query_value(raw, &["requester", "requesterNpub"]),
        })),
        _ => None,
    }
}

#[cfg(debug_assertions)]
fn query_value(raw: &str, names: &[&str]) -> Option<String> {
    let query = raw.split_once('?')?.1.split('#').next().unwrap_or_default();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key);
        if names.iter().any(|name| key == *name) {
            return Some(percent_decode(value));
        }
    }
    None
}

#[cfg(debug_assertions)]
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) =
                    (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
                {
                    out.push(high << 4 | low);
                    index += 3;
                    continue;
                }
                out.push(bytes[index]);
            }
            b'+' => out.push(b' '),
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(debug_assertions)]
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_join_request_links_verbatim() {
        assert_eq!(
            parse(" nvpn://join-request/payload "),
            Some(DeepLink::JoinRequest(
                "nvpn://join-request/payload".to_string()
            ))
        );
    }

    #[test]
    fn join_request_links_route_to_confirmation() {
        assert_eq!(
            route(parse("nvpn://join-request/payload").unwrap()),
            DeepLinkRoute::ConfirmJoinRequest("nvpn://join-request/payload".to_string())
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_links_route_directly_to_debug_actions() {
        assert_eq!(
            route(parse("nvpn://debug/tick").unwrap()),
            DeepLinkRoute::Debug(DebugAction::Tick)
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn parses_debug_accept_join_requester_alias() {
        assert_eq!(
            parse("nvpn://debug/accept-join?network=mesh&requesterNpub=npub1abc"),
            Some(DeepLink::Debug(DebugAction::AcceptJoin {
                network_id: Some("mesh".to_string()),
                requester_npub: Some("npub1abc".to_string())
            }))
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn percent_decodes_debug_accept_join_query_values() {
        assert_eq!(
            parse("nvpn://debug/accept-join?networkId=mesh%2Dalpha&requester=npub1abc%2Bdevice"),
            Some(DeepLink::Debug(DebugAction::AcceptJoin {
                network_id: Some("mesh-alpha".to_string()),
                requester_npub: Some("npub1abc+device".to_string())
            }))
        );
    }
}
