use serde::{Deserialize, Serialize};
use jiff::Timestamp;
use uuid::Uuid;

use uv_configuration::{
    DependencyGroupsWithDefaults, EditableMode, ExtrasSpecificationWithDefaults, InstallOptions,
};
use uv_normalize::PackageName;

use crate::lock::export::{ExportableRequirement, ExportableRequirements};
use crate::{Installable, LockError};

/// An export of a [`Lock`] that renders in CycloneDX SBOM JSON format.
#[derive(Debug)]
pub struct CycloneDxExport<'lock> {
    nodes: Vec<ExportableRequirement<'lock>>,
    project_name: String,
    project_version: String,
    uv_version: String,
}

impl<'lock> CycloneDxExport<'lock> {
    pub fn from_lock(
        target: &impl Installable<'lock>,
        prune: &[PackageName],
        extras: &ExtrasSpecificationWithDefaults,
        dev: &DependencyGroupsWithDefaults,
        annotate: bool,
        _editable: EditableMode,        // Not used for SBOM but needed for signature consistency
        _hashes: bool,                  // CycloneDX handles hashes differently
        install_options: &'lock InstallOptions,
    ) -> Result<Self, LockError> {
        // Extract the packages from the lock file (same as other formats).
        let ExportableRequirements(nodes) = ExportableRequirements::from_lock(
            target,
            prune,
            extras,
            dev,
            annotate,
            install_options,
        );

        // Extract project metadata from the InstallTarget
        let (project_name, project_version) = extract_project_metadata(target);

        Ok(Self {
            nodes,
            project_name,
            project_version,
            uv_version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }

    /// Build a CycloneDX SBOM from the filtered nodes.
    fn build_cyclone_dx_bom(&self) -> CycloneDxBom {
        let mut sbom = create_sbom_template(&self.project_name, &self.project_version, &self.uv_version);

            // Track all components and their dependency types
    use std::collections::HashMap;
        let mut component_scopes: HashMap<String, String> = HashMap::new();
        let mut dependency_map: HashMap<String, Vec<String>> = HashMap::new();

        // Build root dependencies from filtered nodes
        let root_bom_ref = generate_bom_ref(&self.project_name, &self.project_version);
        let mut root_depends_on = Vec::new();

        // Process each filtered node
        for node in &self.nodes {
            let package = node.package;
            let name = package.name().to_string();
            let version = package.version()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let bom_ref = generate_bom_ref(&name, &version);

            // Skip the root project as it's already in metadata
            if bom_ref == root_bom_ref {
                continue;
            }

            // Default scope is required for packages in the filtered set
            component_scopes.insert(bom_ref.clone(), "required".to_string());

            // Collect dependencies from this package
            let mut depends_on = Vec::new();
            for dep in &package.dependencies {
                let dep_name = dep.package_id.name.to_string();
                let dep_version = dep.package_id.version
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let dep_bom_ref = generate_bom_ref(&dep_name, &dep_version);

                // Only include dependencies that are also in our filtered set
                if self.nodes.iter().any(|n| {
                    let n_name = n.package.name().to_string();
                    let n_version = n.package.version().map(|v| v.to_string()).unwrap_or_else(|| "unknown".to_string());
                    generate_bom_ref(&n_name, &n_version) == dep_bom_ref
                }) {
                    depends_on.push(dep_bom_ref);
                }
            }

            dependency_map.insert(bom_ref.clone(), depends_on);

            // Collect root dependencies from dependents
            for dependent in &node.dependents {
                let dep_name = dependent.name().to_string();
                let dep_version = dependent.version()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let dep_bom_ref = generate_bom_ref(&dep_name, &dep_version);

                if dep_bom_ref == root_bom_ref {
                    root_depends_on.push(bom_ref.clone());
                }
            }

            // Create component with appropriate scope
            let scope = component_scopes.get(&bom_ref).cloned();
            let mut component = create_component(&name, &version, "library");
            component.scope = scope;
            sbom.components.push(component);
        }

        // Remove duplicates from root dependencies
        root_depends_on.sort();
        root_depends_on.dedup();

        // Add root dependency entry
        let root_dependency = Dependency {
            reference: root_bom_ref,
            depends_on: root_depends_on,
        };
        sbom.dependencies.push(root_dependency);

        // Add dependency entries for each component
        for node in &self.nodes {
            let package = node.package;
            let name = package.name().to_string();
            let version = package.version()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let bom_ref = generate_bom_ref(&name, &version);

            // Skip the root project
            if bom_ref == generate_bom_ref(&self.project_name, &self.project_version) {
                continue;
            }

            let depends_on = dependency_map.get(&bom_ref).cloned().unwrap_or_default();
            let package_dependency = Dependency {
                reference: bom_ref,
                depends_on,
            };
            sbom.dependencies.push(package_dependency);
        }

        sbom
    }
}

impl std::fmt::Display for CycloneDxExport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Build CycloneDX SBOM from the filtered nodes
        let sbom = self.build_cyclone_dx_bom();
        match serde_json::to_string_pretty(&sbom) {
            Ok(json) => write!(f, "{}", json),
            Err(e) => write!(f, "Error serializing SBOM to JSON: {}", e),
        }
    }
}

// Helper function to extract project metadata from InstallTarget
fn extract_project_metadata<'a>(target: &impl Installable<'a>) -> (String, String) {
    if let Some(project_name) = target.project_name() {
        // Try to get the project version from the root package in the lock
        if let Some(root_package) = target.lock().root() {
            let version = root_package.version()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "0.0.0".to_string());
            (project_name.to_string(), version)
        } else {
            (project_name.to_string(), "0.0.0".to_string())
        }
    } else {
        // Fallback for non-project workspaces or scripts
        ("unknown-project".to_string(), "0.0.0".to_string())
    }
}

/// CycloneDX Software Bill of Materials (SBOM) data structure.
///
/// Represents a minimal CycloneDX 1.6 SBOM with components and dependencies.
#[derive(Debug, Serialize, Deserialize)]
struct CycloneDxBom {
    /// The SBOM format identifier.
    #[serde(rename = "bomFormat")]
    pub bom_format: String,

    /// The CycloneDX specification version.
    #[serde(rename = "specVersion")]
    pub spec_version: String,

    /// A unique serial number for this SBOM.
    #[serde(rename = "serialNumber")]
    pub serial_number: String,

    /// The version of this SBOM.
    pub version: u32,

    /// Metadata about the SBOM creation.
    pub metadata: Metadata,

    /// List of software components.
    pub components: Vec<Component>,

    /// List of dependency relationships.
    pub dependencies: Vec<Dependency>,
}

/// Metadata section of the SBOM containing creation information.
#[derive(Debug, Serialize, Deserialize)]
struct Metadata {
    /// Timestamp when the SBOM was created.
    pub timestamp: String,

    /// List of tools used to create this SBOM.
    pub tools: Vec<Tool>,

    /// The root component that this SBOM describes.
    pub component: Component,
}

/// Information about a tool used to create the SBOM.
#[derive(Debug, Serialize, Deserialize)]
struct Tool {
    /// The vendor of the tool.
    pub vendor: String,

    /// The name of the tool.
    pub name: String,

    /// The version of the tool.
    pub version: String,
}

/// A software component in the SBOM.
#[derive(Debug, Serialize, Deserialize)]
struct Component {
    /// The type of component (e.g., "library", "application").
    #[serde(rename = "type")]
    pub component_type: String,

    /// Unique identifier for this component within the SBOM.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,

    /// The name of the component.
    pub name: String,

    /// The version of the component.
    pub version: String,

    /// Package URL (PURL) identifier for the component.
    pub purl: String,

    /// The scope of the component (e.g., "required", "optional").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Optional cryptographic hashes of the component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<Hash>>,
}

/// Cryptographic hash of a component.
#[derive(Debug, Serialize, Deserialize)]
struct Hash {
    /// The hash algorithm (e.g., "SHA-256").
    pub alg: String,

    /// The hash value in hexadecimal format.
    pub content: String,
}

/// A dependency relationship between components.
#[derive(Debug, Serialize, Deserialize)]
struct Dependency {
    /// Reference to the component that has dependencies.
    #[serde(rename = "ref")]
    pub reference: String,

    /// List of components that this component depends on.
    #[serde(rename = "dependsOn")]
    pub depends_on: Vec<String>,
}

/// Generate a Package URL (PURL) for a Python package.
///
/// Returns a PURL in the format: `pkg:pypi/{name}@{version}`
fn generate_purl(name: &str, version: &str) -> String {
    format!("pkg:pypi/{}@{}", name, version)
}

/// Generate a BOM reference ID for a component.
///
/// Returns a kebab-case ID in the format: `{name}@{version}`
/// This is used as the unique identifier within the SBOM for referencing components.
fn generate_bom_ref(name: &str, version: &str) -> String {
    format!("{}@{}", name, version)
}

/// Create a new CycloneDX SBOM with basic metadata.
///
/// This function creates a minimal SBOM structure with the current timestamp
/// and tool information, including a root component representing the main project.
fn create_sbom_template(project_name: &str, project_version: &str, uv_version: &str) -> CycloneDxBom {
    let timestamp = Timestamp::now().to_string();

    // Create the root component that represents the main project
    let root_component = Component {
        component_type: "application".to_string(),
        bom_ref: generate_bom_ref(project_name, project_version),
        name: project_name.to_string(),
        version: project_version.to_string(),
        purl: generate_purl(project_name, project_version),
        scope: None, // Root component doesn't need scope
        hashes: None,
    };

    CycloneDxBom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.6".to_string(),
        serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
        version: 1,
        metadata: Metadata {
            timestamp,
            tools: vec![Tool {
                vendor: "Astral".to_string(),
                name: "uv".to_string(),
                version: uv_version.to_string(),
            }],
            component: root_component,
        },
        components: Vec::new(),
        dependencies: Vec::new(),
    }
}

/// Create a component for the SBOM.
fn create_component(name: &str, version: &str, component_type: &str) -> Component {
    let purl = generate_purl(name, version);
    let bom_ref = generate_bom_ref(name, version);

    Component {
        component_type: component_type.to_string(),
        bom_ref,
        name: name.to_string(),
        version: version.to_string(),
        purl,
        scope: None,
        hashes: None,
    }
}
