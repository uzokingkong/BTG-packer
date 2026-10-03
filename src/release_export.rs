//! Explicit two-artifact release export, never a directory/cache copy.
//! The local filesystem must not be concurrently modified by an adversary.
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const IMAGE_NAME: &str = "program.exe";
const MANIFEST_NAME: &str = "manifest.json";

/// Non-mutating preflight for a normal build whose final EXE may not exist yet.
pub struct ReleasePlan {
    source: PathBuf,
    destination: PathBuf,
    private_roots: Vec<PathBuf>,
}

impl ReleasePlan {
    pub fn prepare(source: &Path, destination: &Path, private_roots: &[PathBuf]) -> Result<Self> {
        let (source, destination) = checked_paths(source, destination, private_roots)?;
        Ok(Self {
            source,
            destination,
            private_roots: private_roots.to_vec(),
        })
    }

    /// Private diagnostics must never target the planned release directory.
    pub fn check_diagnostic_path(&self, path: &Path) -> Result<()> {
        if within(&normalized(path)?, &self.destination) {
            bail!("private diagnostic path is inside release destination");
        }
        Ok(())
    }

    /// Revalidate all paths after build/cache restoration, then export.
    pub fn finish(&self) -> Result<()> {
        export_final_exe(&self.source, &self.destination, &self.private_roots)
    }
}

/// Export only a selected final EXE and a freshly generated public manifest.
/// Private roots are excluded both as sources and as destination ancestors.
/// Existing destination directories are never reused or overwritten.
pub fn export_final_exe(
    source: &Path,
    destination: &Path,
    private_roots: &[PathBuf],
) -> Result<()> {
    let (source, destination) = checked_paths(source, destination, private_roots)?;
    if !fs::symlink_metadata(&source)?.is_file() {
        bail!("release source is not a regular file");
    }
    export_checked(&source, &destination)
}

fn checked_paths(
    source: &Path,
    destination: &Path,
    private_roots: &[PathBuf],
) -> Result<(PathBuf, PathBuf)> {
    if private_roots.is_empty() {
        bail!("release export requires an explicit private-root policy");
    }
    let source = normalized(source)?;
    let destination = normalized(destination)?;
    let roots = private_roots
        .iter()
        .map(|p| normalized(p))
        .collect::<Result<Vec<_>>>()?;
    for root in &roots {
        if root.try_exists()? && !root.is_dir() {
            bail!("private root must be a directory");
        }
        if within(&source, root) {
            bail!("release source is inside a private root");
        }
        if within(&destination, root) || within(root, &destination) {
            bail!("release destination overlaps a private root");
        }
    }
    if within(&source, &destination) {
        bail!("release source is inside destination");
    }
    reject_links(&source)?;
    reject_links(&destination)?;
    if source.try_exists()? && !fs::symlink_metadata(&source)?.is_file() {
        bail!("release source is not a regular file");
    }
    if source.file_name().is_none_or(|name| {
        !name
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with(".exe")
    }) {
        bail!("release source must be an EXE");
    }
    if destination.try_exists()? {
        bail!("release destination already exists");
    }
    let parent = destination
        .parent()
        .context("release destination has no parent")?;
    if !parent.is_dir() {
        bail!("release parent must already exist");
    }
    Ok((source, destination))
}

fn export_checked(source: &Path, destination: &Path) -> Result<()> {
    let image = fs::read(&source).context("cannot read release EXE")?;
    goblin::pe::PE::parse(&image)
        .map_err(|_| anyhow::anyhow!("release source is not a valid PE"))?;
    let manifest = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": 1,
        "artifact": IMAGE_NAME,
        "output_sha256": format!("{:x}", Sha256::digest(&image)),
        "output_bytes": image.len(),
        "execution_verified": false
    }))?;
    // Validate once more immediately before creating any output. These checks
    // reject links, but are not a handle-based defense against concurrent swaps.
    reject_links(&source)?;
    reject_links(&destination)?;
    fs::create_dir(&destination).context("cannot reserve new release directory")?;
    let image_path = destination.join(IMAGE_NAME);
    let manifest_path = destination.join(MANIFEST_NAME);
    let mut created = Vec::new();
    let result = (|| -> Result<()> {
        reject_links(&destination)?;
        for (path, bytes) in [
            (&image_path, image.as_slice()),
            (&manifest_path, manifest.as_slice()),
        ] {
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            created.push(path.clone());
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        // Inspect the final package list, not only the planned whitelist.
        let mut names = fs::read_dir(&destination)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        names.sort();
        let mut expected = vec![
            std::ffi::OsString::from(IMAGE_NAME),
            std::ffi::OsString::from(MANIFEST_NAME),
        ];
        expected.sort();
        if names != expected {
            bail!("unexpected artifact in release directory");
        }
        reject_links(&image_path)?;
        reject_links(&manifest_path)?;
        if fs::read(&image_path)? != image || fs::read(&manifest_path)? != manifest {
            bail!("release artifact verification failed");
        }
        Ok(())
    })();
    if result.is_err() {
        // Remove only files this operation created, never recursively delete a
        // directory: preserve any unexpected files added by another process.
        if reject_links(&destination).is_ok() {
            for path in created {
                let _ = fs::remove_file(path);
            }
            let _ = fs::remove_dir(&destination);
        }
    }
    result
}

fn normalized(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    if !absolute.is_absolute() {
        bail!("release policy rejects drive-relative paths");
    }
    // Require explicit, unambiguous paths rather than accepting parent traversal.
    if absolute
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        bail!("release policy paths must not contain parent traversal");
    }
    #[cfg(windows)]
    for component in absolute.components() {
        if let Component::Normal(name) = component {
            let text = name.to_string_lossy();
            if text.ends_with('.') || text.ends_with(' ') || text.contains(':') {
                bail!("release policy rejects ambiguous Windows path components");
            }
        }
    }
    reject_links(&absolute)?;
    // Resolve an existing ancestor so policies also cover not-yet-created roots.
    let mut ancestor = absolute.as_path();
    let mut suffix = Vec::new();
    while !ancestor.try_exists()? {
        suffix.push(
            ancestor
                .file_name()
                .context("invalid release policy path")?
                .to_owned(),
        );
        ancestor = ancestor
            .parent()
            .context("release policy path has no existing ancestor")?;
    }
    let mut result = fs::canonicalize(ancestor)?;
    for name in suffix.into_iter().rev() {
        result.push(name);
    }
    Ok(result)
}

fn within(candidate: &Path, root: &Path) -> bool {
    let mut parts = candidate.components();
    root.components().all(|part| {
        parts
            .next()
            .is_some_and(|p| same_component(p.as_os_str(), part.as_os_str()))
    })
}

#[cfg(not(windows))]
fn same_component(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    left == right
}

#[cfg(windows)]
fn same_component(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "Kernel32")]
    extern "system" {
        fn CompareStringOrdinal(
            left: *const u16,
            left_len: i32,
            right: *const u16,
            right_len: i32,
            ignore_case: i32,
        ) -> i32;
    }
    let left: Vec<u16> = left.encode_wide().collect();
    let right: Vec<u16> = right.encode_wide().collect();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    // Both UTF-16 buffers remain alive and their lengths are checked above.
    const CSTR_EQUAL: i32 = 2;
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

fn reject_links(path: &Path) -> Result<()> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        // A Windows drive/verbatim prefix alone is not an absolute filesystem
        // node (e.g. \\?\C:); wait until RootDir is appended before querying it.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    bail!("release policy rejects symbolic links");
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        bail!("release policy rejects reparse points");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "btg-export-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn source(&self) -> PathBuf {
            let source = self.0.join("final.exe");
            fs::write(&source, crate::pe::generate_dummy_target_pe().unwrap()).unwrap();
            source
        }
        fn private(&self) -> Vec<PathBuf> {
            vec![self.0.join("private")]
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn whitelist_exports_only_exe_and_generated_public_manifest() {
        let f = Fixture::new();
        let source = f.source();
        for name in [
            "final.exe.btgmanifest",
            "private-map.json",
            "private-key.bin",
            "cache.pkg",
        ] {
            fs::write(f.0.join(name), b"private-secret-marker").unwrap();
        }
        let destination = f.0.join("release");
        export_final_exe(&source, &destination, &f.private()).unwrap();
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 2);
        let image = fs::read(&source).unwrap();
        assert_eq!(fs::read(destination.join(IMAGE_NAME)).unwrap(), image);
        let text = fs::read_to_string(destination.join(MANIFEST_NAME)).unwrap();
        assert!(!text.contains("private-secret-marker"));
        assert!(!text.contains(&source.to_string_lossy().to_string()));
        let manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            manifest["output_sha256"],
            format!("{:x}", Sha256::digest(&image))
        );
        assert_eq!(manifest["execution_verified"], false);
        assert_eq!(manifest.as_object().unwrap().len(), 5);
    }

    #[test]
    fn private_sources_and_overlapping_destinations_are_rejected() {
        let f = Fixture::new();
        let source = f.source();
        let private = f.0.join("private");
        fs::create_dir(&private).unwrap();
        let hidden_source = private.join("final.exe");
        fs::copy(&source, &hidden_source).unwrap();
        let destination = f.0.join("release");
        assert!(export_final_exe(&hidden_source, &destination, &f.private()).is_err());
        assert!(!destination.exists());
        assert!(export_final_exe(&source, &private.join("release"), &f.private()).is_err());
        assert!(export_final_exe(&source, &destination, &[destination.join("keys")]).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn existing_destination_is_not_overwritten() {
        let f = Fixture::new();
        let source = f.source();
        let destination = f.0.join("release");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join(IMAGE_NAME), b"user-owned").unwrap();
        assert!(export_final_exe(&source, &destination, &f.private()).is_err());
        assert_eq!(
            fs::read(destination.join(IMAGE_NAME)).unwrap(),
            b"user-owned"
        );
    }

    #[test]
    fn invalid_image_or_private_role_does_not_create_destination() {
        let f = Fixture::new();
        let source = f.0.join("key.exe");
        fs::write(&source, b"private-key-marker").unwrap();
        let destination = f.0.join("release");
        assert!(export_final_exe(&source, &destination, &f.private()).is_err());
        assert!(!destination.exists());
        let map = f.0.join("private.json");
        fs::write(&map, crate::pe::generate_dummy_target_pe().unwrap()).unwrap();
        assert!(export_final_exe(&map, &destination, &f.private()).is_err());
        assert!(!destination.exists());
        assert!(export_final_exe(&source, &destination, &[]).is_err());
    }

    #[test]
    fn parent_traversal_is_rejected_before_export() {
        let f = Fixture::new();
        let source = f.source();
        assert!(export_final_exe(&source, &f.0.join("unused/../release"), &f.private()).is_err());
        assert!(!f.0.join("release").exists());
    }

    #[test]
    fn canonical_file_paths_pass_link_checks() {
        let f = Fixture::new();
        let source = f.source();
        reject_links(&fs::canonicalize(source).unwrap()).unwrap();
    }

    #[test]
    fn preflight_is_read_only_and_final_export_rechecks_destination() {
        let f = Fixture::new();
        let source = f.0.join("future.exe");
        let destination = f.0.join("release");
        let plan = ReleasePlan::prepare(&source, &destination, &f.private()).unwrap();
        assert!(!source.exists());
        assert!(!destination.exists());
        assert!(plan
            .check_diagnostic_path(&destination.join("private.log"))
            .is_err());
        assert!(plan.check_diagnostic_path(&f.0.join("build.log")).is_ok());
        fs::write(&source, crate::pe::generate_dummy_target_pe().unwrap()).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("sentinel"), b"user-owned").unwrap();
        assert!(plan.finish().is_err());
        assert_eq!(
            fs::read(destination.join("sentinel")).unwrap(),
            b"user-owned"
        );
    }

    #[cfg(windows)]
    #[test]
    fn missing_root_comparison_is_case_insensitive_and_rejects_path_aliases() {
        let f = Fixture::new();
        let source = f.source();
        assert!(export_final_exe(&source, &f.0.join("PRIVATE"), &f.private()).is_err());
        for name in ["private.", "private ", "private:stream"] {
            assert!(export_final_exe(&source, &f.0.join(name), &f.private()).is_err());
        }
        assert!(!f.0.join("PRIVATE").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_source_and_parent_are_rejected() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        let source = f.source();
        let linked = f.0.join("linked.exe");
        symlink(&source, &linked).unwrap();
        let destination = f.0.join("release");
        assert!(export_final_exe(&linked, &destination, &f.private()).is_err());
        let parent = f.0.join("alias");
        symlink(&f.0, &parent).unwrap();
        assert!(export_final_exe(&source, &parent.join("release"), &f.private()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn junction_sources_roots_and_destination_parents_are_rejected() {
        let f = Fixture::new();
        let source = f.source();
        let private = f.0.join("private");
        fs::create_dir(&private).unwrap();
        fs::copy(&source, private.join("final.exe")).unwrap();
        let alias = f.0.join("private-alias");
        // Junction creation does not need symlink privilege. Both the link and
        // target are inside this test-owned fixture directory.
        let result = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&alias)
            .arg(&private)
            .output()
            .unwrap();
        assert!(result.status.success(), "junction fixture creation failed");
        let destination = f.0.join("release");
        assert!(export_final_exe(&alias.join("final.exe"), &destination, &f.private()).is_err());
        assert!(export_final_exe(&source, &destination, &[alias.clone()]).is_err());
        assert!(export_final_exe(&source, &alias.join("release"), &f.private()).is_err());
        assert!(!destination.exists());
        assert!(!private.join("release").exists());
        // Remove only the junction itself before fixture cleanup.
        fs::remove_dir(alias).unwrap();
    }
}
