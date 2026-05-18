use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use miette::{miette, IntoDiagnostic, Result};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

/// Build a `rustls::ServerConfig` from PEM cert + key files.
pub fn build_server_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    let cert_file = File::open(cert_path)
    .into_diagnostic()
    .map_err(|e| miette!("Cannot open TLS cert '{}': {}", cert_path, e))?;
    let key_file = File::open(key_path)
    .into_diagnostic()
    .map_err(|e| miette!("Cannot open TLS key '{}': {}", key_path, e))?;

    let cert_chain: Vec<Certificate> = certs(&mut BufReader::new(cert_file))
    .into_diagnostic()?
    .into_iter()
    .map(Certificate)
    .collect();

    if cert_chain.is_empty() {
        return Err(miette!("No certificates found in '{}'", cert_path));
    }

    // Try PKCS8 first, fall back to RSA PKCS1
    let mut key_buf = BufReader::new(key_file);
    let key = {
        let pkcs8 = pkcs8_private_keys(&mut key_buf).into_diagnostic()?;
        if let Some(k) = pkcs8.into_iter().next() {
            PrivateKey(k)
        } else {
            // Re-open because BufReader consumed the stream
            let key_file2 = File::open(key_path)
            .into_diagnostic()
            .map_err(|e| miette!("Cannot re-open TLS key '{}': {}", key_path, e))?;
            let rsa = rsa_private_keys(&mut BufReader::new(key_file2))
            .into_diagnostic()?;
            PrivateKey(
                rsa.into_iter()
                .next()
                .ok_or_else(|| miette!("No private key found in '{}'", key_path))?,
            )
        }
    };

    let config = ServerConfig::builder()
    .with_safe_defaults()
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .into_diagnostic()
    .map_err(|e| miette!("Invalid TLS certificate/key: {}", e))?;

    Ok(Arc::new(config))
}

/// Check whether TLS cert/key files are both present.
pub fn tls_files_present(cert: &Option<String>, key: &Option<String>) -> bool {
    match (cert, key) {
        (Some(c), Some(k)) => Path::new(c).exists() && Path::new(k).exists(),
        _ => false,
    }
}
