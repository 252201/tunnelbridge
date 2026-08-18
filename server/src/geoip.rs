use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use reqwest::Client;
use serde::Deserialize;
use tunnelbridge_protocol::GeoLocation;

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
struct CachedLocation {
    location: Option<GeoLocation>,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct GeoIpResolver {
    client: Client,
    endpoint: String,
    cache: std::sync::Arc<DashMap<IpAddr, CachedLocation>>,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct GeoIpResponse {
    #[serde(default, alias = "country")]
    country_name: Option<String>,
    #[serde(default, alias = "countryCode")]
    country_code: Option<String>,
}

impl GeoIpResolver {
    pub fn new(endpoint: String) -> Self {
        let enabled = !endpoint.trim().eq_ignore_ascii_case("off");
        let client = Client::builder()
            .timeout(Duration::from_millis(900))
            .user_agent("TunnelBridge/0.1")
            .build()
            .expect("GeoIP HTTP client should build");
        Self {
            client,
            endpoint,
            cache: std::sync::Arc::new(DashMap::new()),
            enabled,
        }
    }

    pub async fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        if !self.enabled {
            return None;
        }
        let ip = normalize_ip(ip);
        if !is_public_candidate(ip) {
            return None;
        }
        if let Some(cached) = self.cache.get(&ip) {
            if cached.expires_at > Instant::now() {
                return cached.location.clone();
            }
            drop(cached);
            self.cache.remove(&ip);
        }

        let url = endpoint_for(&self.endpoint, ip);
        let location = match self.client.get(url).send().await {
            Ok(response) if response.status().is_success() => response
                .json::<GeoIpResponse>()
                .await
                .ok()
                .and_then(parse_location),
            Ok(_) | Err(_) => None,
        };
        let ttl = if location.is_some() {
            DEFAULT_CACHE_TTL
        } else {
            NEGATIVE_CACHE_TTL
        };
        self.cache.insert(
            ip,
            CachedLocation {
                location: location.clone(),
                expires_at: Instant::now() + ttl,
            },
        );
        location
    }
}

fn endpoint_for(endpoint: &str, ip: IpAddr) -> String {
    if endpoint.contains("{ip}") {
        endpoint.replace("{ip}", &ip.to_string())
    } else {
        format!("{}/{}", endpoint.trim_end_matches('/'), ip)
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        IpAddr::V4(value) => IpAddr::V4(value),
    }
}

fn is_public_candidate(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => {
            let [a, b, _, _] = value.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || a >= 224)
        }
        IpAddr::V6(value) => {
            let first = value.segments()[0];
            !(value.is_loopback()
                || value.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || (first & 0xff00) == 0xff00)
        }
    }
}

fn parse_location(response: GeoIpResponse) -> Option<GeoLocation> {
    let country_code = response.country_code?.trim().to_ascii_uppercase();
    let country_name = response.country_name?.trim().to_owned();
    if country_code.len() != 2
        || !country_code.bytes().all(|byte| byte.is_ascii_uppercase())
        || country_name.is_empty()
    {
        return None;
    }
    Some(GeoLocation {
        country_code,
        country_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ipv4_mapped_ipv6() {
        let value: IpAddr = "::ffff:203.0.113.8".parse().unwrap();
        assert_eq!(
            normalize_ip(value),
            "203.0.113.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn skips_private_and_loopback_addresses() {
        assert!(!is_public_candidate("127.0.0.1".parse().unwrap()));
        assert!(!is_public_candidate("192.168.1.5".parse().unwrap()));
        assert!(!is_public_candidate("fd00::1".parse().unwrap()));
        assert!(is_public_candidate("203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn parses_country_fields_and_normalizes_code() {
        let response = GeoIpResponse {
            country_name: Some(" United States ".into()),
            country_code: Some("us".into()),
        };
        assert_eq!(
            parse_location(response),
            Some(GeoLocation {
                country_code: "US".into(),
                country_name: "United States".into(),
            })
        );
    }

    #[test]
    fn parses_ipwho_response_aliases() {
        let response: GeoIpResponse =
            serde_json::from_str(r#"{"country":"United States","country_code":"US"}"#).unwrap();
        assert_eq!(parse_location(response).unwrap().country_code, "US");
    }

    #[test]
    fn supports_geoip_endpoint_templates() {
        assert_eq!(
            endpoint_for("https://ipwho.is/{ip}", "8.8.8.8".parse().unwrap()),
            "https://ipwho.is/8.8.8.8"
        );
    }
}
