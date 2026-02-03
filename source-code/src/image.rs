use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use miette::{miette, IntoDiagnostic, Result, Context};
use owo_colors::OwoColorize;
use sha2::{Digest, Sha256};
use flate2::read::GzDecoder;
use serde_json::Value;

use crate::container::HACKEROS_LIB;

pub struct ImageManager;

impl ImageManager {
    /// Resolves image layers. If not present, pulls from Docker Hub.
    pub fn resolve_image_layers(image_ref: &str) -> Result<Vec<PathBuf>> {
        // Parse image ref: "ubuntu:latest" -> repo="library/ubuntu", tag="latest"
        let (repo, tag) = parse_image_ref(image_ref);
        let safe_name = format!("{}_{}", repo.replace("/", "_"), tag);
        let image_manifest_dir = PathBuf::from(format!("{}/images/{}", HACKEROS_LIB, safe_name));
        
        if image_manifest_dir.exists() {
            // Read layers from local manifest storage
            return load_layers_from_disk(&image_manifest_dir);
        }

        println!("{} Image {} not found locally. Pulling from registry...", "[NET]".bold().cyan(), image_ref);
        Self::pull_image(&repo, &tag, &image_manifest_dir)
    }

    fn pull_image(repo: &str, tag: &str, dest_dir: &Path) -> Result<Vec<PathBuf>> {
        fs::create_dir_all(dest_dir).into_diagnostic()?;

        // 1. Authenticate (Get Bearer Token)
        let token = get_docker_token(repo)?;

        // 2. Get Manifest
        let manifest_url = format!("https://registry-1.docker.io/v2/{}/manifests/{}", repo, tag);
        let resp = ureq::get(&manifest_url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
            .call().map_err(|e| miette!("Failed to get manifest: {}", e))?;
        
        let manifest_json: Value = resp.into_json().into_diagnostic()?;
        
        // 3. Download Layers
        let layers_dir = PathBuf::from(format!("{}/layers", HACKEROS_LIB));
        fs::create_dir_all(&layers_dir).into_diagnostic()?;
        
        let mut layer_paths = Vec::new();
        
        if let Some(layers) = manifest_json["layers"].as_array() {
            for (i, layer) in layers.iter().enumerate() {
                let digest = layer["digest"].as_str().ok_or(miette!("Missing digest"))?;
                println!("Downloading layer {}/{} ({})", i+1, layers.len(), &digest[0..12]);
                
                let final_layer_path = download_and_extract_layer(repo, &token, digest, &layers_dir)?;
                layer_paths.push(final_layer_path);
            }
        }

        // Save metadata
        let manifest_path = dest_dir.join("layers.json");
        let paths_str: Vec<String> = layer_paths.iter().map(|p| p.to_string_lossy().into()).collect();
        fs::write(manifest_path, serde_json::to_string(&paths_str).unwrap()).into_diagnostic()?;

        Ok(layer_paths)
    }

    pub fn import_tar(path: &Path, name: &str) -> Result<()> {
        println!("{} Importing legacy tarball {}...", "[IMPORT]".bold().yellow(), name);
        // Simple legacy implementation
        let dest = PathBuf::from(format!("{}/images/{}", HACKEROS_LIB, name.replace(":", "_")));
        let l1 = dest.join("layer1");
        fs::create_dir_all(&l1).into_diagnostic()?;
        let file = File::open(path).into_diagnostic()?;
        tar::Archive::new(file).unpack(&l1).into_diagnostic()?;
        
        let manifest = vec![l1.to_string_lossy().to_string()];
        fs::write(dest.join("layers.json"), serde_json::to_string(&manifest).unwrap()).into_diagnostic()?;
        Ok(())
    }
}

fn parse_image_ref(r: &str) -> (String, String) {
    let parts: Vec<&str> = r.split(':').collect();
    let name = parts[0];
    let tag = if parts.len() > 1 { parts[1] } else { "latest" };
    
    // Handle official library images (e.g., "ubuntu" -> "library/ubuntu")
    let repo = if !name.contains('/') {
        format!("library/{}", name)
    } else {
        name.to_string()
    };
    (repo, tag.to_string())
}

fn get_docker_token(repo: &str) -> Result<String> {
    let url = format!("https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull", repo);
    let resp = ureq::get(&url).call().map_err(|e| miette!("Auth failed: {}", e))?;
    let json: Value = resp.into_json().into_diagnostic()?;
    json["token"].as_str().map(|s| s.to_string()).ok_or(miette!("No token in response"))
}

fn download_and_extract_layer(repo: &str, token: &str, digest: &str, base_layer_dir: &Path) -> Result<PathBuf> {
    // SHA256 of digest usually used as folder name
    let clean_digest = digest.replace("sha256:", "");
    let target_dir = base_layer_dir.join(&clean_digest);

    if target_dir.exists() {
        return Ok(target_dir);
    }

    let url = format!("https://registry-1.docker.io/v2/{}/blobs/{}", repo, digest);
    let resp = ureq::get(&url)
        .set("Authorization", &format!("Bearer {}", token))
        .call().map_err(|e| miette!("Download failed: {}", e))?;

    let mut reader = resp.into_reader();
    
    // Download to temp file
    let tmp_tar = std::env::temp_dir().join(format!("{}.tar.gz", clean_digest));
    let mut f = File::create(&tmp_tar).into_diagnostic()?;
    std::io::copy(&mut reader, &mut f).into_diagnostic()?;

    // Extract
    println!("Extracting...");
    fs::create_dir_all(&target_dir).into_diagnostic()?;
    let tar_gz = File::open(&tmp_tar).into_diagnostic()?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(tar);
    
    // Docker layers often have whitedouts/permissions that need root.
    // We try our best to unpack.
    archive.unpack(&target_dir).into_diagnostic().context("Failed to unpack layer")?;
    
    fs::remove_file(tmp_tar).ok();
    Ok(target_dir)
}

fn load_layers_from_disk(manifest_dir: &Path) -> Result<Vec<PathBuf>> {
    let json_path = manifest_dir.join("layers.json");
    let content = fs::read_to_string(json_path).into_diagnostic()?;
    let paths: Vec<String> = serde_json::from_str(&content).into_diagnostic()?;
    Ok(paths.iter().map(PathBuf::from).collect())
      }
