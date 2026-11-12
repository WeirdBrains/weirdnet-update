//! Update manifests and update kinds.

use crate::ids::{check_id, check_text, check_unique};
use crate::rollout::RolloutPlan;
use crate::target::Rule;
use crate::{Error, Hash32, Result, Timestamp};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Most files in one update.
pub const MAX_FILES: usize = 10_000;
/// Most capabilities one update may request.
pub const MAX_CAPABILITIES: usize = 256;
/// Longest file path.
pub const MAX_PATH: usize = 512;

/// Operating systems in the WeirdBrains platform matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum Platform {
    Linux,
    Macos,
    Windows,
    Android,
    Ios,
    Freebsd,
    Openbsd,
    Ghostbsd,
    Dragonfly,
}

impl Platform {
    /// The lowercase name used in targeting rules.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Freebsd => "freebsd",
            Self::Openbsd => "openbsd",
            Self::Ghostbsd => "ghostbsd",
            Self::Dragonfly => "dragonfly",
        }
    }
}

/// CPU architectures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum Arch {
    X86_64,
    Aarch64,
}

/// How a full package reaches the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum PackageFormat {
    TarGz,
    Zip,
    Deb,
    Rpm,
    PkgTarZst,
    Nix,
    Homebrew,
    Winget,
    App,
    Dmg,
    Exe,
    Msi,
    Apk,
    Ipa,
    BsdPkg,
}

/// What the client does with a verified full package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallMode {
    /// User-level swap of a versioned directory or bundle (tar.gz, zip, .app, standalone exe).
    Swap,
    /// The platform installer shows its own confirmation (APK `PackageInstaller`, MSI, dmg, ipa).
    PlatformInstaller,
    /// Run the system package manager after a user-approved privilege prompt (deb, rpm, BSD pkg).
    PrivilegedPackageManager,
    /// Never install: tell the user the command (TAUR, Nix, Homebrew, winget own these files).
    NotifyOnly,
}

impl PackageFormat {
    /// The install path for this format. Nothing escalates privileges without a prompt.
    pub fn install_mode(self) -> InstallMode {
        match self {
            Self::TarGz | Self::Zip | Self::App | Self::Exe => InstallMode::Swap,
            Self::Dmg | Self::Msi | Self::Apk | Self::Ipa => InstallMode::PlatformInstaller,
            Self::Deb | Self::Rpm | Self::BsdPkg => InstallMode::PrivilegedPackageManager,
            Self::PkgTarZst | Self::Nix | Self::Homebrew | Self::Winget => InstallMode::NotifyOnly,
        }
    }
}

/// A full, signed replacement build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullPackage {
    /// Target OS.
    pub platform: Platform,
    /// Target CPU.
    pub arch: Arch,
    /// Package format.
    pub format: PackageFormat,
    /// The platform signing identity the package must keep (APK cert SHA-256, Apple Team ID,
    /// Authenticode subject). The client compares it with the running build's.
    pub signing_identity: String,
}

/// A Dart code patch. **Placeholder:** the format is reserved so manifests can name it, but no
/// client accepts it yet (Android/desktop AOT swap is Salty Gull G6, the iOS interpreter G9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartPatch {
    /// Engine build the patch was made against.
    pub engine_hash: String,
    /// Target OS.
    pub platform: Platform,
    /// Target CPU.
    pub arch: Arch,
}

/// What an update carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateKind {
    /// Non-code resources: images, fonts, translations, Remote Flutter Widgets files, config.
    Assets,
    /// WebAssembly components for the `weirdnet-ext` host (Pulley interpreter on iOS).
    Wasm {
        /// Host ABI version the components target; the client refuses other versions.
        host_abi: u32,
    },
    /// A whole new build.
    Full(FullPackage),
    /// Reserved: see [`DartPatch`].
    DartPatch(DartPatch),
    /// "A new version is in the store." Downloads nothing.
    StoreNotice {
        /// Store page to open.
        url: String,
    },
}

impl UpdateKind {
    /// Short name for errors and logs.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Assets => "assets",
            Self::Wasm { .. } => "wasm",
            Self::Full(_) => "full",
            Self::DartPatch(_) => "dart-patch",
            Self::StoreNotice { .. } => "store-notice",
        }
    }
}

/// Security advisory severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A security label: shown with a distinct badge, never installed without consent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityLabel {
    /// Severity.
    pub severity: Severity,
    /// The publisher's advisory text.
    pub advisory: String,
}

/// Display labels.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Labels {
    /// Set for security updates.
    #[serde(default)]
    pub security: Option<SecurityLabel>,
    /// The publisher recommends this update.
    #[serde(default)]
    pub recommended: bool,
}

/// One file of an update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path inside the update (`/`-separated, no `..`).
    pub path: String,
    /// Exact size in bytes.
    pub size: u64,
    /// BLAKE3 of the content.
    pub blake3: Hash32,
}

impl FileEntry {
    /// An entry describing `data` at `path`.
    pub fn describe(path: &str, data: &[u8]) -> Self {
        Self { path: path.to_owned(), size: data.len() as u64, blake3: Hash32::of(data) }
    }

    /// Checks downloaded bytes against the entry.
    pub fn verify(&self, data: &[u8]) -> Result<()> {
        let mut v = self.verifier();
        v.update(data)?;
        v.finish()
    }

    /// An incremental checker for streamed or chunked downloads.
    pub fn verifier(&self) -> FileVerifier<'_> {
        FileVerifier { entry: self, hasher: blake3::Hasher::new(), seen: 0 }
    }

    fn validate(&self) -> Result<()> {
        let p = &self.path;
        let bad = p.is_empty()
            || p.len() > MAX_PATH
            || p.starts_with('/')
            || p.contains('\\')
            || p.contains('\0')
            || p.split('/').any(|c| c.is_empty() || c == "." || c == "..")
            || p.as_bytes().get(1) == Some(&b':');
        if bad {
            return Err(Error::File { path: p.clone(), reason: "unsafe or malformed path".into() });
        }
        Ok(())
    }
}

/// Incremental size and hash check; fails as soon as more bytes arrive than declared.
pub struct FileVerifier<'a> {
    entry: &'a FileEntry,
    hasher: blake3::Hasher,
    seen: u64,
}

impl FileVerifier<'_> {
    /// Feeds the next bytes.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        self.seen = self.seen.saturating_add(data.len() as u64);
        if self.seen > self.entry.size {
            return Err(Error::File { path: self.entry.path.clone(), reason: "larger than declared".into() });
        }
        self.hasher.update(data);
        Ok(())
    }

    /// Checks the final size and hash.
    pub fn finish(self) -> Result<()> {
        if self.seen != self.entry.size {
            return Err(Error::File { path: self.entry.path.clone(), reason: "size mismatch".into() });
        }
        if Hash32::from(self.hasher.finalize()) != self.entry.blake3 {
            return Err(Error::File { path: self.entry.path.clone(), reason: "hash mismatch".into() });
        }
        Ok(())
    }
}

/// A signed description of one update on one channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// App id.
    pub app: String,
    /// Channel (stable, beta, custom).
    pub channel: String,
    /// Unique id of this update.
    pub update_id: String,
    /// Per-(app, channel) sequence number; strictly increasing.
    pub seq: u64,
    /// What the update carries.
    pub kind: UpdateKind,
    /// Version of the build or bundle.
    pub version: Version,
    /// Base releases this applies to; empty means any.
    #[serde(default)]
    pub base_releases: Vec<String>,
    /// Files and their hashes.
    #[serde(default)]
    pub files: Vec<FileEntry>,
    /// Lowest client version this applies to.
    #[serde(default)]
    pub min_client: Option<Version>,
    /// Highest client version this applies to.
    #[serde(default)]
    pub max_client: Option<Version>,
    /// Capabilities requested (Wasm modules). New ones always ask again.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Display labels.
    #[serde(default)]
    pub labels: Labels,
    /// On-device targeting rule; `None` targets everyone.
    #[serde(default)]
    pub targeting: Option<Rule>,
    /// Staged rollout; `None` means 100%.
    #[serde(default)]
    pub rollout: Option<RolloutPlan>,
    /// Set when this record rolls back to an older build: names the update it replaces, and
    /// allows a lower version.
    #[serde(default)]
    pub rollback_of: Option<String>,
    /// Release notes.
    #[serde(default)]
    pub notes: String,
    /// Creation time.
    pub created: Timestamp,
    /// Expiry; always enforced.
    pub expires: Timestamp,
}

impl UpdateManifest {
    /// Structural checks.
    pub fn validate(&self) -> Result<()> {
        check_id("app", &self.app)?;
        check_id("channel", &self.channel)?;
        check_id("update id", &self.update_id)?;
        if self.expires <= self.created {
            return Err(Error::invalid("manifest", "expires must be after created"));
        }
        for b in &self.base_releases {
            check_id("base release", b)?;
        }
        if let (Some(lo), Some(hi)) = (&self.min_client, &self.max_client)
            && lo > hi
        {
            return Err(Error::invalid("manifest", "min_client above max_client"));
        }
        if self.files.len() > MAX_FILES {
            return Err(Error::invalid("manifest", format!("more than {MAX_FILES} files")));
        }
        let mut paths = BTreeSet::new();
        for f in &self.files {
            f.validate()?;
            if !paths.insert(f.path.as_str()) {
                return Err(Error::File { path: f.path.clone(), reason: "listed twice".into() });
            }
        }
        match &self.kind {
            UpdateKind::StoreNotice { url } => {
                if !self.files.is_empty() {
                    return Err(Error::invalid("manifest", "a store notice carries no files"));
                }
                if !url.starts_with("https://") || url.len() > 2048 {
                    return Err(Error::invalid("manifest", "store url must be https"));
                }
            }
            _ if self.files.is_empty() => return Err(Error::invalid("manifest", "no files")),
            UpdateKind::Full(p) => check_id("signing identity", &p.signing_identity)?,
            UpdateKind::DartPatch(p) => check_id("engine hash", &p.engine_hash)?,
            UpdateKind::Assets | UpdateKind::Wasm { .. } => {}
        }
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(Error::invalid("manifest", format!("more than {MAX_CAPABILITIES} capabilities")));
        }
        for c in &self.capabilities {
            check_id("capability", c)?;
        }
        check_unique("capabilities", &self.capabilities)?;
        if let Some(s) = &self.labels.security {
            check_text("advisory", &s.advisory)?;
        }
        check_text("notes", &self.notes)?;
        if let Some(r) = &self.rollback_of {
            check_id("rollback_of", r)?;
        }
        if let Some(rule) = &self.targeting {
            rule.validate()?;
        }
        if let Some(plan) = &self.rollout {
            plan.validate()?;
        }
        Ok(())
    }

    /// `app/channel`, for messages.
    pub fn target(&self) -> String {
        format!("{}/{}", self.app, self.channel)
    }

    /// Total bytes to download.
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).fold(0u64, u64::saturating_add)
    }
}
