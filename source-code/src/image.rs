use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use miette::{miette, IntoDiagnostic, Result, Context};
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};
use flate2::read::GzDecoder;
use serde_json::Value;
use ureq::{Agent, AgentBuilder};

use crate::container::HACKEROS_LIB;

pub struct ImageManager;

impl ImageManager {
    /// Pobiera warstwy obrazu. Jeśli nie ma go lokalnie, ściąga z rejestru.
    pub fn resolve_image_layers(image_ref: &str) -> Result<Vec<PathBuf>> {
        let (registry, repo, tag) = parse_image_ref(image_ref);
        let safe_name = format!("{}_{}_{}", registry.replace("/", "_"), repo.replace("/", "_"), tag);
        let image_dir = PathBuf::from(format!("{}/images/{}", HACKEROS_LIB, safe_name));

        if image_dir.exists() {
            return load_layers_from_disk(&image_dir);
        }

        println!("{} Pulling {}...", "[NET]".bold().cyan(), image_ref);
        Self::pull_image(&registry, &repo, &tag, &image_dir)
    }

    /// Pobiera obraz z rejestru i zapisuje warstwy.
    fn pull_image(registry: &str, repo: &str, tag: &str, dest_dir: &Path) -> Result<Vec<PathBuf>> {
        fs::create_dir_all(dest_dir).into_diagnostic()?;

        let token = get_auth_token(registry, repo)?;
        let agent = AgentBuilder::new().build();

        let manifest_url = format!("https://{}/v2/{}/manifests/{}", registry, repo, tag);
        let resp = agent
        .get(&manifest_url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
        .call()
        .map_err(|e| miette!("Failed to get manifest: {}", e))?;

        let manifest_json: Value = resp.into_json().into_diagnostic()?;

        // Obsługa manifest list (multi‑arch) oraz pojedynczego manifestu
        let (layers, config_digest) = if let Some(manifests) = manifest_json["manifests"].as_array() {
            let arch = std::env::consts::ARCH;
            let os = std::env::consts::OS;
            let selected = manifests
            .iter()
            .find(|m| {
                m["platform"]["architecture"].as_str() == Some(arch)
                && m["platform"]["os"].as_str() == Some(os)
            })
            .ok_or_else(|| miette!("No matching platform found for {}/{}", os, arch))?;
            let digest = selected["digest"]
            .as_str()
            .ok_or(miette!("Missing digest in manifest list"))?;

            let manifest_url = format!("https://{}/v2/{}/manifests/{}", registry, repo, digest);
            let resp = agent
            .get(&manifest_url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
            .call()
            .map_err(|e| miette!("Failed to get manifest for digest {}: {}", digest, e))?;
            let manifest: Value = resp.into_json().into_diagnostic()?;
            let layers = manifest["layers"]
            .as_array()
            .ok_or(miette!("Manifest has no layers"))?
            .clone();
            let config_digest = manifest["config"]["digest"]
            .as_str()
            .unwrap_or("")
            .to_string();
            (layers, config_digest)
        } else {
            let layers = manifest_json["layers"]
            .as_array()
            .ok_or(miette!("Manifest has no layers"))?
            .clone();
            let config_digest = manifest_json["config"]["digest"]
            .as_str()
            .unwrap_or("")
            .to_string();
            (layers, config_digest)
        };

        // Pobierz plik konfiguracyjny (opcjonalny)
        if !config_digest.is_empty() {
            download_config(registry, repo, &token, &config_digest, dest_dir)?;
        }

        // Pobierz i rozpakuj warstwy
        let layers_dir = PathBuf::from(format!("{}/layers", HACKEROS_LIB));
        fs::create_dir_all(&layers_dir).into_diagnostic()?;

        let mut layer_paths = Vec::new();
        for (i, layer) in layers.iter().enumerate() {
            let digest = layer["digest"]
            .as_str()
            .ok_or(miette!("Missing digest"))?;
            println!("Downloading layer {}/{} ({})", i + 1, layers.len(), &digest[0..12]);
            let layer_path = download_and_extract_layer(registry, repo, &token, digest, &layers_dir)?;
            layer_paths.push(layer_path);
        }

        // Zapisz manifest (listę ścieżek warstw) w katalogu obrazu
        let manifest_path = dest_dir.join("layers.json");
        let paths_str: Vec<String> = layer_paths
        .iter()
        .map(|p| p.to_string_lossy().into())
        .collect();
        fs::write(&manifest_path, serde_json::to_string(&paths_str).unwrap())
        .into_diagnostic()
        .wrap_err("Failed to write layers.json")?;

        // Skopiuj plik konfiguracyjny (jeśli istnieje) do katalogu obrazu
        if !config_digest.is_empty() {
            let config_path = dest_dir.join("config.json");
            let config_file = dest_dir.join(format!("{}.json", config_digest.replace("sha256:", "")));
            if config_file.exists() {
                fs::copy(&config_file, &config_path).ok();
            }
        }

        Ok(layer_paths)
    }

    /// Importuje obraz z archiwum tar (legacy).
    pub fn import_tar(path: &Path, name: &str) -> Result<()> {
        println!("{} Importing legacy tarball {}...", "[IMPORT]".bold().yellow(), name);
        let safe_name = name.replace(":", "_");
        let dest = PathBuf::from(format!("{}/images/{}", HACKEROS_LIB, safe_name));
        let layer1 = dest.join("layer1");
        fs::create_dir_all(&layer1).into_diagnostic()?;

        let file = File::open(path).into_diagnostic()?;
        let mut archive = tar::Archive::new(file);
        archive.unpack(&layer1).into_diagnostic()?;

        let manifest = vec![layer1.to_string_lossy().to_string()];
        fs::write(dest.join("layers.json"), serde_json::to_string(&manifest).unwrap())
        .into_diagnostic()?;

        Ok(())
    }
}

// ------------------------------------------------------------
// Funkcje pomocnicze
// ------------------------------------------------------------

fn parse_image_ref(r: &str) -> (String, String, String) {
    let parts: Vec<&str> = r.split('/').collect();
    let registry: String;
    let repo_path: String;
    let tag: String;

    if parts.len() == 1 {
        registry = "registry-1.docker.io".to_string();
        let repo_tag = parts[0];
        let repo = repo_tag.split(':').next().unwrap();
        tag = repo_tag.split(':').nth(1).unwrap_or("latest").to_string();
        repo_path = format!("library/{}", repo);
    } else if parts.len() == 2 {
        if parts[0].contains('.') || parts[0].contains(':') {
            registry = parts[0].to_string();
            let repo_tag = parts[1];
            let repo = repo_tag.split(':').next().unwrap();
            tag = repo_tag.split(':').nth(1).unwrap_or("latest").to_string();
            repo_path = repo.to_string();
        } else {
            registry = "registry-1.docker.io".to_string();
            let repo_tag = parts[1];
            let repo = repo_tag.split(':').next().unwrap();
            tag = repo_tag.split(':').nth(1).unwrap_or("latest").to_string();
            repo_path = format!("{}/{}", parts[0], repo);
        }
    } else {
        registry = parts[0].to_string();
        let repo_tag = parts[1..].join("/");
        let repo = repo_tag.split(':').next().unwrap();
        tag = repo_tag.split(':').nth(1).unwrap_or("latest").to_string();
        repo_path = repo.to_string();
    }

    (registry, repo_path, tag)
}

fn get_auth_token(registry: &str, repo: &str) -> Result<String> {
    let auth_url = if registry == "registry-1.docker.io" {
        format!("https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull", repo)
    } else {
        format!("https://{}/token?service={}&scope=repository:{}:pull", registry, registry, repo)
    };

    let resp = ureq::get(&auth_url)
    .call()
    .map_err(|e| miette!("Authentication request failed: {}", e))?;
    let json: Value = resp.into_json().into_diagnostic()?;
    json["token"]
    .as_str()
    .map(|s| s.to_string())
    .ok_or_else(|| miette!("No token in response"))
}

fn download_and_extract_layer(
    registry: &str,
    repo: &str,
    token: &str,
    digest: &str,
    base_layer_dir: &Path,
) -> Result<PathBuf> {
    let clean_digest = digest.replace("sha256:", "");
    let target_dir = base_layer_dir.join(&clean_digest);

    if target_dir.exists() {
        return Ok(target_dir);
    }

    let url = format!("https://{}/v2/{}/blobs/{}", registry, repo, digest);
    let resp = ureq::get(&url)
    .set("Authorization", &format!("Bearer {}", token))
    .call()
    .map_err(|e| miette!("Download failed: {}", e))?;

    let tmp_tar = std::env::temp_dir().join(format!("{}.tar.gz", clean_digest));
    {
        let mut reader = resp.into_reader();
        let mut f = File::create(&tmp_tar).into_diagnostic()?;
        std::io::copy(&mut reader, &mut f).into_diagnostic()?;
    }

    // Weryfikacja sumy kontrolnej
    let mut hasher = Sha256::new();
    let mut file = File::open(&tmp_tar).into_diagnostic()?;
    std::io::copy(&mut file, &mut hasher).into_diagnostic()?;
    let computed = format!("sha256:{:x}", hasher.finalize());
    if computed != digest {
        return Err(miette!("Digest mismatch: expected {}, got {}", digest, computed));
    }

    fs::create_dir_all(&target_dir).into_diagnostic()?;
    let tar_gz = File::open(&tmp_tar).into_diagnostic()?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(tar);
    archive.unpack(&target_dir).into_diagnostic()?;

    fs::remove_file(tmp_tar).ok();
    Ok(target_dir)
}

fn download_config(registry: &str, repo: &str, token: &str, digest: &str, dest_dir: &Path) -> Result<()> {
    let clean_digest = digest.replace("sha256:", "");
    let config_file = dest_dir.join(format!("{}.json", clean_digest));
    if config_file.exists() {
        return Ok(());
    }

    let url = format!("https://{}/v2/{}/blobs/{}", registry, repo, digest);
    let resp = ureq::get(&url)
    .set("Authorization", &format!("Bearer {}", token))
    .call()
    .map_err(|e| miette!("Failed to download config: {}", e))?;

    let mut reader = resp.into_reader();
    let mut f = File::create(&config_file).into_diagnostic()?;
    std::io::copy(&mut reader, &mut f).into_diagnostic()?;
    Ok(())
}

fn load_layers_from_disk(manifest_dir: &Path) -> Result<Vec<PathBuf>> {
    let json_path = manifest_dir.join("layers.json");
    let content = fs::read_to_string(&json_path)
    .into_diagnostic()
    .wrap_err_with(|| format!("Failed to read layers.json from {}", manifest_dir.display()))?;
    let paths: Vec<String> = serde_json::from_str(&content).into_diagnostic()?;
    Ok(paths.iter().map(PathBuf::from).collect())
}
