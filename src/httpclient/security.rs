use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{redirect, ClientBuilder};
use url::{Host, Url};

pub(crate) fn client_builder(url: &str) -> anyhow::Result<ClientBuilder> {
    let url = Url::parse(url)?;
    // Only unit-test builds may start requests at loopback mock servers.
    let local_mock = cfg!(test) && matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback());
    if !local_mock {
        validate_url(&url)?;
    }

    Ok(reqwest::Client::builder()
        .user_agent(crate::USER_AGENT)
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(300))
        .no_proxy()
        .dns_resolver(Arc::new(PublicResolver))
        .redirect(redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > 5 {
                attempt.error("Too many content redirects")
            } else if let Err(error) = validate_url(attempt.url()) {
                attempt.error(error)
            } else {
                attempt.follow()
            }
        })))
}

fn validate_url(url: &Url) -> io::Result<()> {
    let allowed = matches!(url.scheme(), "http" | "https")
        && match url.host() {
            None => false,
            Some(Host::Domain(_)) => true,
            Some(Host::Ipv4(ip)) => is_public_ip(ip.into()),
            Some(Host::Ipv6(ip)) => is_public_ip(ip.into()),
        };
    if allowed {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Content URL must use HTTP(S) and a public destination",
        ))
    }
}

struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((name.as_str(), 0)).await?;
            // Return the checked addresses directly to the connector. Never look up
            // the hostname a second time, which would permit DNS rebinding.
            Ok(checked_addresses(addresses)?)
        })
    }
}

fn checked_addresses(addresses: impl Iterator<Item = SocketAddr>) -> io::Result<Addrs> {
    let addresses: Vec<_> = addresses.collect();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Content hostname must resolve exclusively to public destinations",
        ))
    } else {
        Ok(Box::new(addresses.into_iter()))
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !matches!(
            ip.octets(),
            [0 | 10 | 127, ..]
                | [100, 64..=127, ..]
                | [169, 254, ..]
                | [172, 16..=31, ..]
                | [192, 0, 0 | 2, _]
                | [192, 88, 99, _]
                | [192, 168, ..]
                | [198, 18..=19, ..]
                | [198, 51, 100, _]
                | [203, 0, 113, _]
                | [224..=255, ..]
        ),
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4() {
                return is_public_ip(ipv4.into());
            }
            let segments = ip.segments();
            if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let octets = ip.octets();
                return is_public_ip(
                    Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]).into(),
                );
            }
            // Restrict native IPv6 to global unicast, excluding special-use,
            // documentation and deprecated 6to4 prefixes.
            matches!(segments, [0x2000..=0x3fff, ..])
                && !matches!(
                    segments,
                    [0x2001, 0..=0x1ff | 0xdb8, ..] | [0x2002, ..] | [0x3fff, 0..=0xfff, ..]
                )
        }
    }
}

#[cfg(test)]
mod is_public_ip_tests {
    use super::*;

    #[test]
    fn classifies_ipv4_ranges_and_boundaries() {
        for (ip, expected) in [
            ("0.0.0.0", false),
            ("0.255.255.255", false),
            ("1.0.0.0", true),
            ("9.255.255.255", true),
            ("10.0.0.0", false),
            ("10.255.255.255", false),
            ("11.0.0.0", true),
            ("100.63.255.255", true),
            ("100.64.0.0", false),
            ("100.127.255.255", false),
            ("100.128.0.0", true),
            ("126.255.255.255", true),
            ("127.0.0.0", false),
            ("127.255.255.255", false),
            ("128.0.0.0", true),
            ("169.253.255.255", true),
            ("169.254.0.0", false),
            ("169.254.255.255", false),
            ("169.255.0.0", true),
            ("172.15.255.255", true),
            ("172.16.0.0", false),
            ("172.31.255.255", false),
            ("172.32.0.0", true),
            ("191.255.255.255", true),
            ("192.0.0.0", false),
            ("192.0.0.255", false),
            ("192.0.1.0", true),
            ("192.0.1.255", true),
            ("192.0.2.0", false),
            ("192.0.2.255", false),
            ("192.0.3.0", true),
            ("192.88.98.255", true),
            ("192.88.99.0", false),
            ("192.88.99.255", false),
            ("192.88.100.0", true),
            ("192.167.255.255", true),
            ("192.168.0.0", false),
            ("192.168.255.255", false),
            ("192.169.0.0", true),
            ("198.17.255.255", true),
            ("198.18.0.0", false),
            ("198.19.255.255", false),
            ("198.20.0.0", true),
            ("198.51.99.255", true),
            ("198.51.100.0", false),
            ("198.51.100.255", false),
            ("198.51.101.0", true),
            ("203.0.112.255", true),
            ("203.0.113.0", false),
            ("203.0.113.255", false),
            ("203.0.114.0", true),
            ("223.255.255.255", true),
            ("224.0.0.0", false),
            ("239.255.255.255", false),
            ("240.0.0.0", false),
            ("255.255.255.255", false),
            ("8.8.8.8", true),
        ] {
            assert_eq!(is_public_ip(ip.parse().unwrap()), expected, "{ip}");
        }
    }

    #[test]
    fn classifies_ipv6_ranges_and_embedded_ipv4() {
        for (ip, expected) in [
            ("::", false),
            ("::1", false),
            ("::127.0.0.1", false),
            ("::8.8.8.8", true),
            ("::ffff:127.0.0.1", false),
            ("::ffff:10.0.0.1", false),
            ("::ffff:8.8.8.8", true),
            ("64:ff9b::127.0.0.1", false),
            ("64:ff9b::192.168.1.1", false),
            ("64:ff9b::8.8.8.8", true),
            ("64:ff9b:1::808:808", false),
            ("100::1", false),
            ("100:0:0:1::1", false),
            ("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2000::", true),
            ("2001::", false),
            ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:200::", true),
            ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:db8::", false),
            ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:db9::", true),
            ("2002::", false),
            ("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2003::", true),
            ("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("3fff::", false),
            ("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("3fff:1000::", true),
            ("4000::", false),
            ("fc00::", false),
            ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("fe80::", false),
            ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("ff00::", false),
            ("2001:4860:4860::8888", true),
            ("2606:4700:4700::1111", true),
        ] {
            assert_eq!(is_public_ip(ip.parse().unwrap()), expected, "{ip}");
        }
    }
}

#[cfg(test)]
mod validate_url_tests {
    use super::*;

    #[test]
    fn rejects_private_ip_literals_and_non_http_schemes() {
        for url in [
            "http://127.0.0.1/",
            "http://2130706433/",
            "http://0177.0.0.1/",
            "http://0x7f000001/",
            "https://10.1.2.3/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[64:ff9b::a00:1]/",
            "file:///etc/passwd",
            "ftp://example.com/file",
        ] {
            assert_eq!(
                validate_url(&Url::parse(url).unwrap()).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied,
                "{url}"
            );
        }
    }

    #[test]
    fn accepts_public_ip_literals_and_domain_names() {
        for url in [
            "https://example.com/file",
            "http://8.8.8.8/",
            "https://[2606:4700:4700::1111]/",
        ] {
            validate_url(&Url::parse(url).unwrap()).unwrap();
        }
    }
}

#[cfg(test)]
mod checked_addresses_tests {
    use super::*;

    #[test]
    fn returns_the_exact_checked_addresses() {
        let addresses = [
            "8.8.8.8:0".parse().unwrap(),
            "[2606:4700:4700::1111]:0".parse().unwrap(),
        ];
        assert_eq!(
            checked_addresses(addresses.into_iter())
                .unwrap()
                .collect::<Vec<_>>(),
            addresses
        );
    }

    #[test]
    fn rejects_empty_private_and_mixed_dns_answers() {
        for addresses in [
            vec![],
            vec!["127.0.0.1:0"],
            vec!["8.8.8.8:0", "10.0.0.1:0"],
            vec!["[::1]:0"],
        ] {
            assert_eq!(
                checked_addresses(
                    addresses
                        .into_iter()
                        .map(|address| address.parse().unwrap())
                )
                .err()
                .unwrap()
                .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
}

#[cfg(test)]
mod public_resolver_tests {
    use super::*;

    #[tokio::test]
    async fn rejects_localhost_from_the_system_resolver() {
        assert!(PublicResolver
            .resolve("localhost".parse().unwrap())
            .await
            .is_err());
    }
}

#[cfg(test)]
mod client_builder_tests {
    use super::*;

    struct PendingResolver;

    impl Resolve for PendingResolver {
        fn resolve(&self, _: Name) -> Resolving {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn bounds_dns_resolution_by_connect_timeout() {
        let url = "http://never-resolves.invalid/";
        let client = client_builder(url)
            .unwrap()
            .dns_resolver(Arc::new(PendingResolver))
            .build()
            .unwrap();
        let start = tokio::time::Instant::now();
        let error = client.get(url).send().await.unwrap_err();

        assert!(error.is_timeout());
        assert!(error.is_connect());
        assert_eq!(start.elapsed(), Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn bounds_the_total_request_time() {
        let url = "http://never-resolves.invalid/";
        let client = client_builder(url)
            .unwrap()
            .dns_resolver(Arc::new(PendingResolver))
            .connect_timeout(Duration::from_secs(600))
            .read_timeout(Duration::from_secs(600))
            .build()
            .unwrap();
        let start = tokio::time::Instant::now();
        let error = client.get(url).send().await.unwrap_err();

        assert!(error.is_timeout());
        assert_eq!(start.elapsed(), Duration::from_secs(300));
    }
}
