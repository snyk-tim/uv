/// The format to use when exporting a `uv.lock` file.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ExportFormat {
    /// Export in `requirements.txt` format.
    #[default]
    #[serde(rename = "requirements.txt", alias = "requirements-txt")]
    #[cfg_attr(
        feature = "clap",
        clap(name = "requirements.txt", alias = "requirements-txt")
    )]
    RequirementsTxt,
    /// Export in `pylock.toml` format.
    #[serde(rename = "pylock.toml", alias = "pylock-toml")]
    #[cfg_attr(feature = "clap", clap(name = "pylock.toml", alias = "pylock-toml"))]
    PylockToml,
    /// Export in CycloneDX 1.6 JSON format (Software Bill of Materials).
    #[serde(rename = "cyclonedx1.6+json")]
    #[cfg_attr(feature = "clap", clap(name = "cyclonedx1.6+json"))]
    CycloneDx16Json,
}
