//! Network operators (@ipMatch).

use super::traits::{ByteOperatorResult, Operator, OperatorResult};
use crate::error::{Error, Result};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// IP match operator (@ipMatch).
pub struct IpMatchOperator {
    networks: Vec<IpNetwork>,
}

impl IpMatchOperator {
    /// Create from a comma- and/or whitespace-separated IP/CIDR list.
    pub fn new(ips: &str) -> Result<Self> {
        let entries = ips.split(|c: char| c == ',' || c.is_whitespace());
        Self::from_entries(entries, ips)
    }

    /// Create from a file containing IPs/CIDRs.
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| Error::RuleFileLoad {
            path: path.into(),
            source: e,
        })?;
        let entries = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .flat_map(|line| line.split(','));
        Self::from_entries(entries, path)
    }

    fn from_entries<'a>(entries: impl Iterator<Item = &'a str>, source: &str) -> Result<Self> {
        let networks = entries
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                Self::parse_network(s).map_err(|err| Error::InvalidIp {
                    value: source.to_owned(),
                    message: format!("{s}: {err}"),
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self { networks })
    }

    fn parse_network(s: &str) -> std::result::Result<IpNetwork, ipnetwork::IpNetworkError> {
        s.parse::<IpNetwork>()
            .and_then(|net| match (net, net.network().to_canonical()) {
                // Go net.IPNet.Contains tests the masked network number. For
                // example ::ffff:192.0.2.8/95 has an IPv6 network number,
                // while /96 and longer retain the full mapped prefix.
                (IpNetwork::V6(v6), IpAddr::V4(ip)) => {
                    IpNetwork::new(IpAddr::V4(ip), v6.prefix() - 96)
                }
                _ => Ok(net),
            })
    }

    pub(super) fn from_dataset(records: &[String]) -> Self {
        // Coraza splits IP records only at commas and skips malformed entries.
        let networks = records
            .iter()
            .flat_map(|s| s.split(','))
            .filter_map(|s| {
                let s = s.trim();
                if let Some((_, prefix)) = s.split_once('/') {
                    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
                        return None;
                    }
                }
                Self::parse_network(s).ok()
            })
            .collect();
        Self { networks }
    }

    /// Check if an IP is in any of the networks.
    fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.networks.iter().any(|net| net.contains(ip))
    }
}

impl Operator for IpMatchOperator {
    fn execute_bytes(&self, value: &[u8]) -> crate::Result<ByteOperatorResult> {
        Ok(match std::str::from_utf8(value) {
            Ok(text) => self.execute(text).into(),
            Err(_) => ByteOperatorResult::no_match(),
        })
    }

    fn execute(&self, value: &str) -> OperatorResult {
        if let Ok(ip) = value.parse::<IpAddr>() {
            if self.contains(ip) {
                return OperatorResult::matched(value.to_string());
            }
        }
        OperatorResult::no_match()
    }

    fn name(&self) -> &'static str {
        "ipMatch"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_match_single() {
        let op = IpMatchOperator::new("192.168.1.1").unwrap();
        assert!(op.execute("192.168.1.1").matched);
        assert!(!op.execute("192.168.1.2").matched);
    }

    #[test]
    fn ipv4_mapped_networks_and_addresses_use_the_ipv4_mask() {
        for prefix in ["192.0.2.8/24", "::ffff:192.0.2.8/120"] {
            let op = IpMatchOperator::new(prefix).unwrap();
            for addr in ["192.0.2.7", "::ffff:c000:207"] {
                let result = op.execute_bytes(addr.as_bytes()).unwrap();
                assert_eq!(result.matched_value.as_deref(), Some(addr.as_bytes()));
            }
            for addr in ["198.51.100.2", "::ffff:198.51.100.2", "::192.0.2.7"] {
                assert!(!op.execute(addr).matched, "{prefix} {addr}");
            }
        }
    }

    #[test]
    fn the_masked_network_number_determines_the_address_family() {
        // /95 clears one bit in the mapping prefix. The resulting network
        // and ::/0 match only native IPv6. /96 maps to IPv4's default route.
        let addresses = ["192.0.2.8", "::ffff:c000:208", "::fffe:c000:208", "::1"];
        for (prefix, expected) in [
            ("::ffff:192.0.2.8/95", [false, false, true, false]),
            ("::ffff:192.0.2.8/96", [true, true, false, false]),
            ("::/0", [false, false, true, true]),
        ] {
            let op = IpMatchOperator::new(prefix).unwrap();
            assert_eq!(
                addresses.map(|ip| op.execute(ip).matched),
                expected,
                "{prefix}"
            );
        }
    }

    #[test]
    fn invalid_mapped_prefix_rejects_an_otherwise_valid_list() {
        let entries = "::ffff:192.0.2.8/120,::ffff:192.0.2.8/129";
        assert!(matches!(
            IpMatchOperator::new(entries),
            Err(Error::InvalidIp { .. })
        ));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("list.data");
        std::fs::write(&path, entries).unwrap();
        assert!(matches!(
            IpMatchOperator::from_file(path.to_str().unwrap()),
            Err(Error::InvalidIp { .. })
        ));
    }

    #[test]
    fn test_ip_match_cidr() {
        let op = IpMatchOperator::new("192.168.1.0/24").unwrap();
        assert!(op.execute("192.168.1.1").matched);
        assert!(op.execute("192.168.1.255").matched);
        assert!(!op.execute("192.168.2.1").matched);
    }

    #[test]
    fn test_ip_match_multiple() {
        let op = IpMatchOperator::new("10.0.0.0/8 192.168.0.0/16").unwrap();
        assert!(op.execute("10.1.2.3").matched);
        assert!(op.execute("192.168.1.1").matched);
        assert!(!op.execute("172.16.0.1").matched);
    }

    #[test]
    fn test_ip_match_comma_separated() {
        // CRS REQUEST-905 uses the comma-separated form, e.g. "127.0.0.1,::1".
        let op = IpMatchOperator::new("127.0.0.1,::1").unwrap();
        assert!(op.execute("127.0.0.1").matched);
        assert!(op.execute("::1").matched);
        assert!(!op.execute("10.0.0.1").matched);
    }

    #[test]
    fn test_ip_match_comma_and_space_mixed() {
        let op = IpMatchOperator::new("10.0.0.0/8, 192.168.0.0/16").unwrap();
        assert!(op.execute("10.1.2.3").matched);
        assert!(op.execute("192.168.1.1").matched);
    }
}
