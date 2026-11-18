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
                s.parse::<IpNetwork>().map_err(|err| Error::InvalidIp {
                    value: source.to_owned(),
                    message: format!("{s}: {err}"),
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self { networks })
    }

    /// Check if an IP is in any of the networks.
    fn contains(&self, ip: &IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(*ip))
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
            if self.contains(&ip) {
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
