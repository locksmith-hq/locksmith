//! Local CA for explicit-proxy mode (design D4). The CA carries a critical NameConstraints
//! extension: permitted DNS = the enabled hosts, every IP address excluded, so a stolen CA key
//! cannot impersonate any other site. Its private key lives in the vault (never on disk in
//! plaintext); only the public certificate is written out and added to trust stores.

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

/// Vault location of the CA private key (a reserved project).
pub const KEY_PROJECT: &str = "_locksmith";
pub const KEY_ENV: &str = "development";
pub const KEY_NAME: &str = "HTTP_CA_KEY";

/// Explicit-proxy files under the config dir: the public CA certificate and the hosts it is
/// constrained to (one per line). The private key is in the vault.
pub fn cert_path(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("http").join("ca.pem")
}

pub fn hosts_path(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("http").join("ca-hosts")
}

/// Enabled hosts; empty when the CA is not installed.
pub fn enabled_hosts(config_dir: &std::path::Path) -> Vec<String> {
    if !cert_path(config_dir).is_file() {
        return Vec::new();
    }
    std::fs::read_to_string(hosts_path(config_dir))
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Leaf validity; leaves are minted on demand and cached only in daemon memory.
const LEAF_DAYS: i64 = 30;
const CA_DAYS: i64 = 3650;

pub struct NewCa {
    pub cert_pem: String,
    /// PKCS#8 PEM. Goes into the vault only.
    pub key_pem: Zeroizing<String>,
    pub common_name: String,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// `*.x.com` permits `x.com` and below (RFC 5280 dNSName subtrees cover subdomains).
fn subtree(host: &str) -> String {
    let h = host.trim_start_matches("*.");
    h.rsplit_once(':')
        .map_or(h, |(n, _)| n)
        .to_ascii_lowercase()
}

/// A new name-constrained CA for `hosts` (at least one).
pub fn generate(hosts: &[String]) -> Result<NewCa, String> {
    if hosts.is_empty() {
        return Err("the CA needs at least one enabled host".into());
    }
    let key = KeyPair::generate().map_err(err)?;
    let id = crate::http::new_token();
    let common_name = format!("Locksmith Local CA {}", &id[4..12]);
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name.as_str());
    dn.push(DnType::OrganizationName, "Locksmith (this machine only)");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut permitted: Vec<String> = hosts.iter().map(|h| subtree(h)).collect();
    permitted.sort();
    permitted.dedup();
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: permitted.into_iter().map(GeneralSubtree::DnsName).collect(),
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    });
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(CA_DAYS);
    let cert = p.self_signed(&key).map_err(err)?;
    Ok(NewCa {
        cert_pem: cert.pem(),
        key_pem: Zeroizing::new(key.serialize_pem()),
        common_name,
    })
}

/// A leaf for `host` signed by the CA: (chain leaf+CA, private key).
pub fn leaf(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    host: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let ca_key = KeyPair::from_pem(ca_key_pem).map_err(err)?;
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key).map_err(err)?;
    let key = KeyPair::generate().map_err(err)?;
    let mut p = CertificateParams::new(vec![host.to_string()]).map_err(err)?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host);
    p.distinguished_name = dn;
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(LEAF_DAYS);
    let cert = p.signed_by(&key, &issuer).map_err(err)?;
    let ca_der = x509_parser::pem::parse_x509_pem(ca_cert_pem.as_bytes())
        .map_err(err)?
        .1
        .contents;
    let chain = vec![cert.der().clone(), CertificateDer::from(ca_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok((chain, key))
}

/// TLS server config for a leaf (HTTP/1.1 only).
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(err)?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(err)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// What `smith doctor` checks about an installed CA certificate.
#[derive(Debug, Clone, PartialEq)]
pub struct CaInfo {
    pub subject: String,
    pub is_ca: bool,
    /// The NameConstraints extension is present and critical.
    pub constrained: bool,
    pub permitted_dns: Vec<String>,
    /// Both IPv4 and IPv6 are excluded entirely.
    pub excludes_ip: bool,
    pub not_after: i64,
}

pub fn inspect(cert_pem: &str) -> Result<CaInfo, String> {
    use x509_parser::extensions::GeneralName;
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).map_err(err)?;
    let cert = pem.parse_x509().map_err(err)?;
    let nc = cert.name_constraints().map_err(err)?;
    let mut permitted_dns = Vec::new();
    let (mut v4, mut v6) = (false, false);
    if let Some(nc) = &nc {
        for s in nc.value.permitted_subtrees.iter().flatten() {
            if let GeneralName::DNSName(d) = s.base {
                permitted_dns.push(d.to_string());
            }
        }
        for s in nc.value.excluded_subtrees.iter().flatten() {
            if let GeneralName::IPAddress(ip) = s.base {
                v4 |= ip == [0u8; 8];
                v6 |= ip == [0u8; 32];
            }
        }
    }
    Ok(CaInfo {
        subject: cert.subject().to_string(),
        is_ca: cert.is_ca(),
        constrained: nc.as_ref().is_some_and(|n| n.critical),
        permitted_dns,
        excludes_ip: v4 && v6,
        not_after: cert.validity().not_after.timestamp(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};

    fn verify(ca_pem: &str, chain: &[CertificateDer<'static>], name: &str) -> Result<(), String> {
        let ca_der = x509_parser::pem::parse_x509_pem(ca_pem.as_bytes())
            .unwrap()
            .1
            .contents;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca_der)).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let v =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap();
        v.verify_server_cert(
            &chain[0],
            &chain[1..],
            &ServerName::try_from(name.to_string()).unwrap(),
            &[],
            UnixTime::now(),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    #[test]
    fn name_constraints_bind_the_ca_to_enabled_hosts() {
        let ca = generate(&["api.enabled.test".into(), "*.shop.test".into()]).unwrap();
        assert!(ca.key_pem.contains("PRIVATE KEY") && !ca.cert_pem.contains("PRIVATE"));
        let info = inspect(&ca.cert_pem).unwrap();
        assert!(
            info.is_ca && info.constrained && info.excludes_ip,
            "{info:?}"
        );
        assert_eq!(info.permitted_dns, ["api.enabled.test", "shop.test"]);
        assert!(info.subject.contains(&ca.common_name));

        let (chain, _) = leaf(&ca.cert_pem, &ca.key_pem, "api.enabled.test").unwrap();
        verify(&ca.cert_pem, &chain, "api.enabled.test").unwrap();
        let (chain, _) = leaf(&ca.cert_pem, &ca.key_pem, "a.shop.test").unwrap();
        verify(&ca.cert_pem, &chain, "a.shop.test").unwrap();
        // A leaf the CA signs for any other name is rejected because of the constraints.
        let (chain, _) = leaf(&ca.cert_pem, &ca.key_pem, "example.org").unwrap();
        let e = verify(&ca.cert_pem, &chain, "example.org").unwrap_err();
        assert!(e.to_lowercase().contains("name"), "{e}");
        let (chain, key) = leaf(&ca.cert_pem, &ca.key_pem, "api.enabled.test").unwrap();
        assert!(server_config(chain, key).is_ok());
        assert!(generate(&[]).is_err());
    }
}
