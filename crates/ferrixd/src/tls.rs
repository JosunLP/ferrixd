//! TLS configuration.
//!
//! Uses `rustls` with the `ring` crypto provider — a fully memory-safe TLS
//! stack with no OpenSSL FFI, structurally immune to the Heartbleed class of
//! bug. The provider is passed explicitly so the daemon does not
//! depend on process-global crypto-provider state.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

/// A hot-swappable server-side TLS configuration shared by every TLS listener
/// (`tls_bind`, `wss_bind`, the S2S link listener). Listeners build a fresh
/// [`TlsAcceptor`] from the current config on each accept, so `REHASH` can
/// install a renewed certificate/key without dropping the process or any live
/// connection — only handshakes started after the swap use the new material.
#[derive(Debug)]
pub struct SharedServerTls {
    config: RwLock<Arc<ServerConfig>>,
}

impl SharedServerTls {
    /// Wrap an initial [`ServerConfig`] in a shared, swappable holder.
    #[must_use]
    pub fn new(config: Arc<ServerConfig>) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(config),
        })
    }

    /// A [`TlsAcceptor`] over the current configuration. Cheap: it only clones
    /// the inner `Arc`, so callers build one per accepted connection.
    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.config.read().clone())
    }

    /// Rebuild the server configuration from `cfg` and swap it in atomically.
    /// Connections handshaking after this call use the new certificate/key;
    /// existing connections are unaffected.
    ///
    /// # Errors
    ///
    /// Returns an error (leaving the current config in place) if the new
    /// certificate material cannot be loaded — so a bad `REHASH` never disarms
    /// the listener.
    pub fn reload(&self, cfg: &TlsConfig) -> Result<()> {
        let rebuilt = build_server_config(cfg)?;
        self.install(rebuilt);
        Ok(())
    }

    /// Swap in an already-built configuration (see [`build_server_config`]).
    ///
    /// Lets `REHASH` stage/validate the new material first and commit it only
    /// after every other part of the reload has succeeded.
    pub fn install(&self, config: Arc<ServerConfig>) {
        *self.config.write() = config;
    }
}

/// Load the daemon's certificate chain and private key from its TLS config.
fn cert_material(
    cfg: &TlsConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    match (&cfg.cert, &cfg.key) {
        (Some(cert_path), Some(key_path)) => {
            let certs = load_certs(cert_path).with_context(|| {
                format!("loading certificate chain from {}", cert_path.display())
            })?;
            let key = load_key(key_path)
                .with_context(|| format!("loading private key from {}", key_path.display()))?;
            Ok((certs, key))
        }
        _ if cfg.self_signed_dev => generate_self_signed(&cfg.dev_hostnames)
            .context("generating self-signed development certificate"),
        // Validation in `Config::validate` guarantees we never reach here.
        _ => anyhow::bail!("no TLS certificate source configured"),
    }
}

/// Build a shared [`ServerConfig`] from the daemon's TLS configuration.
pub fn build_server_config(cfg: &TlsConfig) -> Result<Arc<ServerConfig>> {
    let (certs, key) = cert_material(cfg)?;

    // Pin the crypto provider explicitly rather than relying on the global
    // default, and restrict to safe protocol versions (TLS 1.2 + 1.3).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // Request (but do not require) a client certificate so SASL EXTERNAL and S2S
    // links can use its fingerprint. We deliberately do NOT validate the chain —
    // trust is established later by matching the fingerprint.
    let verifier = Arc::new(client_verifier::AcceptAnyClientCert(provider.clone()));
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("installing certificate and key")?;

    Ok(Arc::new(config))
}

/// A rustls client config for outbound S2S links: it presents this server's own
/// certificate (so the peer can pin it) and accepts the peer's certificate
/// without chain validation (trust is the pinned fingerprint).
pub fn build_link_client_config(cfg: &TlsConfig) -> Result<Arc<rustls::ClientConfig>> {
    let (certs, key) = cert_material(cfg)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(link_verifier::AcceptAnyServerCert(provider)))
        .with_client_auth_cert(certs, key)
        .context("installing link client certificate")?;
    Ok(Arc::new(config))
}

/// The SHA-256 fingerprint (lowercase hex) of a certificate's DER encoding —
/// the identity used for SASL EXTERNAL and S2S link pinning.
#[must_use]
pub fn cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// A freshly generated self-signed certificate, ready to write to disk.
#[derive(Debug, Clone)]
pub struct GeneratedCert {
    /// PEM-encoded certificate.
    pub cert_pem: String,
    /// PEM-encoded PKCS#8 private key.
    pub key_pem: String,
    /// The certificate's SHA-256 fingerprint (lowercase hex) — the value to pin
    /// in `[[links]]` or list in an account's `fingerprints`.
    pub fingerprint: String,
}

/// Generate a self-signed certificate + key pair (PEM) for the given hostnames.
///
/// Unlike the in-memory dev certificate used at startup, this returns durable
/// PEM text for the `gen-cert` subcommand to persist.
///
/// # Errors
///
/// Returns an error if certificate generation fails.
pub fn generate_self_signed_pem(hostnames: &[String]) -> Result<GeneratedCert> {
    let names: Vec<String> = if hostnames.is_empty() {
        vec!["localhost".to_owned()]
    } else {
        hostnames.to_vec()
    };
    let certified =
        rcgen::generate_simple_self_signed(names).context("generating self-signed certificate")?;
    let fingerprint = cert_fingerprint(certified.cert.der());
    Ok(GeneratedCert {
        cert_pem: certified.cert.pem(),
        key_pem: certified.signing_key.serialize_pem(),
        fingerprint,
    })
}

/// Compute the SHA-256 fingerprint (lowercase hex) of the first certificate in a
/// PEM file — the identity a peer would pin (`[[links]].fingerprint`) or an
/// account would allow for SASL EXTERNAL (`fingerprints`).
///
/// # Errors
///
/// Returns an error if the file cannot be read or contains no certificate.
pub fn fingerprint_file(path: &Path) -> Result<String> {
    let certs =
        load_certs(path).with_context(|| format!("reading certificate from {}", path.display()))?;
    let first = certs.first().context("PEM file contained no certificate")?;
    Ok(cert_fingerprint(first))
}

/// A client-certificate verifier that accepts any certificate without chain
/// validation. Trust is enforced downstream by fingerprint (see module docs).
mod client_verifier {
    use std::sync::Arc;

    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

    #[derive(Debug)]
    pub(super) struct AcceptAnyClientCert(pub(super) Arc<CryptoProvider>);

    impl ClientCertVerifier for AcceptAnyClientCert {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }

        fn client_auth_mandatory(&self) -> bool {
            false // optional: clients may connect without a certificate
        }

        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, Error> {
            Ok(ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

/// A server-certificate verifier for outbound links that accepts any cert (trust
/// is the pinned fingerprint, checked after the handshake).
mod link_verifier {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub(super) struct AcceptAnyServerCert(pub(super) Arc<CryptoProvider>);

    impl ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .context("opening certificate PEM file")?
        .collect::<Result<Vec<_>, _>>()
        .context("parsing certificate PEM file")?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in PEM file");
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).context("reading private key PEM file")
}

/// Generate an ephemeral self-signed certificate for the given hostnames.
///
/// Development only — the key exists only in memory for the process lifetime.
fn generate_self_signed(
    hostnames: &[String],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let names: Vec<String> = if hostnames.is_empty() {
        vec!["localhost".to_owned()]
    } else {
        hostnames.to_vec()
    };
    let certified = rcgen::generate_simple_self_signed(names)?;
    let cert_der = certified.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    Ok((vec![cert_der], PrivateKeyDer::Pkcs8(key_der)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::TlsConfig;
    use std::path::PathBuf;

    fn dev_config() -> TlsConfig {
        TlsConfig {
            cert: None,
            key: None,
            self_signed_dev: true,
            dev_hostnames: vec!["localhost".to_owned()],
        }
    }

    #[test]
    fn reload_swaps_config_and_bad_material_leaves_it_armed() {
        let initial = build_server_config(&dev_config()).unwrap();
        let shared = SharedServerTls::new(initial);
        // A fresh dev config reloads cleanly.
        shared.reload(&dev_config()).unwrap();
        let armed = Arc::as_ptr(&shared.config.read().clone());

        // A config pointing at nonexistent cert material must fail the reload
        // without disarming the listener (the previous config stays in place).
        let bad = TlsConfig {
            cert: Some(PathBuf::from("/nonexistent/cert.pem")),
            key: Some(PathBuf::from("/nonexistent/key.pem")),
            self_signed_dev: false,
            dev_hostnames: Vec::new(),
        };
        assert!(shared.reload(&bad).is_err());
        // The armed config is unchanged after the failed reload.
        assert_eq!(armed, Arc::as_ptr(&shared.config.read().clone()));
        // And an acceptor is still obtainable.
        let _ = shared.acceptor();
    }
}
