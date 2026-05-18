use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Duration;

use miette::{miette, IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};
use flate2::read::GzDecoder;
use serde_json::Value;
use tracing::info;

use crate::container::HACKEROS_LIB;

const MANIFEST_TIMEOUT_SECS: u64 = 30;
const LAYER_TIMEOUT_SECS: u64 = 300;

pub struct ImageManager;

impl ImageManager {
    pub fn resolve_image_layers(image_ref: &str) -> Result<Vec<PathBuf>> {
        let (registry, repo, tag) = parse_image_ref(image_ref);
        let safe_name = format!(
            "{}_{}_{}",
            registry.replace('/', "_"),
                                repo.replace('/', "_"),
                                tag
        );
        let image_dir =
        PathBuf::from(format!("{}/images/{}", HACKEROS_LIB, safe_name));

        if image_dir.exists() {
            info!(image = image_ref, "Image cache hit");
            return load_layers_from_disk(&image_dir);
        }

        println!("{} Pulling {}...", "[NET]".bold().cyan(), image_ref.yellow());
        Self::pull_image(&registry, &repo, &tag, &image_dir)
    }

    fn pull_image(
        registry: &str,
        repo: &str,
        tag: &str,
        dest_dir: &Path,
    ) -> Result<Vec<PathBuf>> {
        fs::create_dir_all(dest_dir).into_diagnostic()?;

        let token = get_auth_token(registry, repo)?;
        let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(MANIFEST_TIMEOUT_SECS))
        .build();

        let manifest_url =
        format!("https://{}/v2/{}/manifests/{}", registry, repo, tag);
            let resp = agent
            .get(&manifest_url)
            .set("Authorization", &format!("Bearer {}", token))
            .set(
                "Accept",
                 "application/vnd.docker.distribution.manifest.v2+json, \
application/vnd.oci.image.manifest.v1+json, \
application/vnd.docker.distribution.manifest.list.v2+json",
            )
            .call()
            .map_err(|e| miette!("Failed to get manifest: {}", e))?;

            let manifest_json: Value = resp.into_json().into_diagnostic()?;

            let (layers, config_digest) =
            if let Some(manifests) = manifest_json["manifests"].as_array() {
                let arch = std::env::consts::ARCH;
                let os = std::env::consts::OS;
                let selected = manifests
                .iter()
                .find(|m| {
                    m["platform"]["architecture"].as_str() == Some(arch)
                    && m["platform"]["os"].as_str() == Some(os)
                })
                .ok_or_else(|| miette!("No image for {}/{}", os, arch))?;
                let digest = selected["digest"]
                .as_str()
                .ok_or_else(|| miette!("Missing digest in manifest list"))?;
                let inner_url =
                format!("https://{}/v2/{}/manifests/{}", registry, repo, digest);
                    let inner: Value = agent
                    .get(&inner_url)
                    .set("Authorization", &format!("Bearer {}", token))
                    .set(
                        "Accept",
                         "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .call()
                    .map_err(|e| miette!("Failed to get platform manifest: {}", e))?
                    .into_json()
                    .into_diagnostic()?;
                    let ls = inner["layers"]
                    .as_array()
                    .ok_or_else(|| miette!("Manifest has no layers"))?
                    .clone();
                    let cd = inner["config"]["digest"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                    (ls, cd)
            } else {
                let ls = manifest_json["layers"]
                .as_array()
                .ok_or_else(|| miette!("Manifest has no layers"))?
                .clone();
                let cd = manifest_json["config"]["digest"]
                .as_str()
                .unwrap_or("")
                .to_string();
                (ls, cd)
            };

            if !config_digest.is_empty() {
                download_config(registry, repo, &token, &config_digest, dest_dir)?;
            }

            let layers_dir = PathBuf::from(format!("{}/layers", HACKEROS_LIB));
            fs::create_dir_all(&layers_dir).into_diagnostic()?;

            let mut layer_paths = Vec::new();
            let total = layers.len();
            for (i, layer) in layers.iter().enumerate() {
                let digest = layer["digest"]
                .as_str()
                .ok_or_else(|| miette!("Missing layer digest at {}", i))?;
                let size_mb = layer["size"]
                .as_u64()
                .map(|b| format!("{:.1} MB", b as f64 / 1_048_576.0))
                .unwrap_or_else(|| "?".into());
                // Fix E0599: convert &str slice to String before calling .dimmed()
                let short_digest = digest[..16].to_string();
                println!(
                    "  {} Layer {}/{} {} ({})",
                         "↓".cyan(),
                         i + 1,
                         total,
                         short_digest.dimmed(),
                         size_mb
                );
                let lp = download_and_extract_layer(
                    registry, repo, &token, digest, &layers_dir,
                )?;
                layer_paths.push(lp);
            }

            let paths_str: Vec<String> = layer_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
            fs::write(
                dest_dir.join("layers.json"),
                      serde_json::to_string(&paths_str).unwrap(),
            )
            .into_diagnostic()
            .wrap_err("Failed to write layers.json")?;

            println!(
                "{} Pulled {}",
                "[OK]".bold().green(),
                     format!("{}/{}/{}", registry, repo, tag).green()
            );
            Ok(layer_paths)
    }

    pub fn import_tar(path: &Path, name: &str) -> Result<()> {
        println!(
            "{} Importing {}...",
            "[IMPORT]".bold().yellow(),
                 name.yellow()
        );
        let safe_name = name.replace(':', "_");
        let dest =
        PathBuf::from(format!("{}/images/{}", HACKEROS_LIB, safe_name));
        let layer1 = dest.join("layer1");
        fs::create_dir_all(&layer1).into_diagnostic()?;
        let file = File::open(path).into_diagnostic()?;
        let mut archive = tar::Archive::new(file);
        archive.unpack(&layer1).into_diagnostic()?;
        let manifest = vec![layer1.to_string_lossy().to_string()];
        fs::write(
            dest.join("layers.json"),
                  serde_json::to_string(&manifest).unwrap(),
        )
        .into_diagnostic()?;
        println!("{} Imported {}", "[OK]".bold().green(), name.green());
        Ok(())
    }

    pub fn gc_unused_layers() -> Result<()> {
        let images_dir = PathBuf::from(format!("{}/images", HACKEROS_LIB));
        let layers_dir = PathBuf::from(format!("{}/layers", HACKEROS_LIB));
        if !layers_dir.exists() {
            return Ok(());
        }

        let mut referenced = std::collections::HashSet::new();
        if let Ok(entries) = fs::read_dir(&images_dir) {
            for entry in entries.flatten() {
                if let Ok(content) =
                    fs::read_to_string(entry.path().join("layers.json"))
                    {
                        if let Ok(paths) =
                            serde_json::from_str::<Vec<String>>(&content)
                            {
                                for p in paths {
                                    referenced.insert(p);
                                }
                            }
                    }
            }
        }

        let mut removed = 0usize;
        for entry in fs::read_dir(&layers_dir).into_diagnostic()? {
            let path = entry.into_diagnostic()?.path();
            if path.is_dir()
                && !referenced.contains(&path.to_string_lossy().into_owned())
                {
                    fs::remove_dir_all(&path).ok();
                    removed += 1;
                }
        }

        if removed > 0 {
            println!(
                "{} GC: removed {} unused layer(s)",
                     "[GC]".bold().magenta(),
                     removed
            );
        } else {
            println!("{} No unused layers found", "[GC]".bold().magenta());
        }
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_image_ref(r: &str) -> (String, String, String) {
    let parts: Vec<&str> = r.splitn(3, '/').collect();
    match parts.as_slice() {
        [name_tag] => {
            let (repo, tag) = split_tag(name_tag);
            (
                "registry-1.docker.io".into(),
             format!("library/{}", repo),
                 tag,
            )
        }
        [ns, name_tag] if !ns.contains('.') && !ns.contains(':') => {
            let (repo, tag) = split_tag(name_tag);
            (
                "registry-1.docker.io".into(),
             format!("{}/{}", ns, repo),
                 tag,
            )
        }
        [registry, rest @ ..] => {
            let combined = rest.join("/");
            let (repo, tag) = split_tag(&combined);
            (registry.to_string(), repo, tag)
        }
        _ => (
            "registry-1.docker.io".into(),
              "library/alpine".into(),
              "latest".into(),
        ),
    }
}

fn split_tag(s: &str) -> (String, String) {
    match s.rsplit_once(':') {
        Some((r, t)) => (r.to_string(), t.to_string()),
        None => (s.to_string(), "latest".to_string()),
    }
}

fn get_auth_token(registry: &str, repo: &str) -> Result<String> {
    let auth_url = if registry == "registry-1.docker.io" {
        format!(
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
            repo
        )
    } else {
        format!(
            "https://{}/token?service={}&scope=repository:{}:pull",
            registry, registry, repo
        )
    };
    let agent = ureq::AgentBuilder::new()
    .timeout(Duration::from_secs(15))
    .build();
    let resp = agent
    .get(&auth_url)
    .call()
    .map_err(|e| miette!("Auth failed for {}: {}", auth_url, e))?;
    let json: Value = resp.into_json().into_diagnostic()?;
    json["token"]
    .as_str()
    .map(|s| s.to_string())
    .ok_or_else(|| miette!("No token in auth response"))
}

fn download_and_extract_layer(
    registry: &str,
    repo: &str,
    token: &str,
    digest: &str,
    base: &Path,
) -> Result<PathBuf> {
    let clean = digest.replace("sha256:", "");
    let target = base.join(&clean);
    if target.exists() {
        return Ok(target);
    }

    let url = format!("https://{}/v2/{}/blobs/{}", registry, repo, digest);
    let agent = ureq::AgentBuilder::new()
    .timeout_connect(Duration::from_secs(10))
    .timeout(Duration::from_secs(LAYER_TIMEOUT_SECS))
    .build();
    let resp = agent
    .get(&url)
    .set("Authorization", &format!("Bearer {}", token))
    .call()
    .map_err(|e| {
        // Fix E0599: convert &str slice to String
        let short = digest[..16].to_string();
        miette!("Download layer {}: {}", short, e)
    })?;

    let tmp = std::env::temp_dir().join(format!("hco_{}.tar.gz", clean));
    {
        let mut r = resp.into_reader();
        let mut f = File::create(&tmp).into_diagnostic()?;
        std::io::copy(&mut r, &mut f).into_diagnostic()?;
    }

    // Verify SHA256 digest
    let mut hasher = Sha256::new();
    std::io::copy(
        &mut File::open(&tmp).into_diagnostic()?,
                  &mut hasher,
    )
    .into_diagnostic()?;
    let computed = format!("sha256:{:x}", hasher.finalize());
    if computed != digest {
        fs::remove_file(&tmp).ok();
        let short = digest[..16].to_string();
        return Err(miette!(
            "Digest mismatch for {}: got {}",
            short,
            computed
        ));
    }

    fs::create_dir_all(&target).into_diagnostic()?;
    let tar = GzDecoder::new(File::open(&tmp).into_diagnostic()?);
    let mut archive = tar::Archive::new(tar);
    archive.set_preserve_permissions(true);
    archive
    .unpack(&target)
    .into_diagnostic()
    .wrap_err_with(|| {
        let short = digest[..16].to_string();
        format!("Extracting layer {}", short)
    })?;
    fs::remove_file(tmp).ok();
    Ok(target)
}

fn download_config(
    registry: &str,
    repo: &str,
    token: &str,
    digest: &str,
    dest: &Path,
) -> Result<()> {
    let clean = digest.replace("sha256:", "");
    let config_file = dest.join(format!("{}.json", clean));
    if config_file.exists() {
        return Ok(());
    }
    let url = format!("https://{}/v2/{}/blobs/{}", registry, repo, digest);
    let agent = ureq::AgentBuilder::new()
    .timeout(Duration::from_secs(30))
    .build();
    let resp = agent
    .get(&url)
    .set("Authorization", &format!("Bearer {}", token))
    .call()
    .map_err(|e| miette!("Download config: {}", e))?;
    let mut r = resp.into_reader();
    let mut f = File::create(&config_file).into_diagnostic()?;
    std::io::copy(&mut r, &mut f).into_diagnostic()?;
    Ok(())
}

fn load_layers_from_disk(dir: &Path) -> Result<Vec<PathBuf>> {
    let content = fs::read_to_string(dir.join("layers.json"))
    .into_diagnostic()
    .wrap_err_with(|| {
        format!("Failed to read layers.json from {}", dir.display())
    })?;
    let paths: Vec<String> = serde_json::from_str(&content).into_diagnostic()?;
    Ok(paths.iter().map(PathBuf::from).collect())
}
