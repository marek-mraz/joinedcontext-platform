//! `kind: Organization` specification and validation (T-0111, PF-01, PF-02, PF-25, PF-41).

use crate::envelope::{self, Kind, ObjectMeta, Scope};
use crate::error::{Error, Result};
use crate::names;
use crate::urn::Urn;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Desired specification of an [`Organization`][crate::kinds::Organization] resource (PF-01, PF-02, PF-25, PF-41).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OrganizationSpec {
    /// Verified internet FQDN, the `{orgDomain}` of every entity URN (PF-41).
    pub domain: String,
    /// Git repository URL of the one Org Repository in Gitea (PF-02).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_repository_url: Option<String>,
    /// Ordered list of supported locales, most preferred first (PF-25).
    pub locales: Vec<String>,
    /// Organization fallback default locale, MUST be one of [`Self::locales`] (PF-25, PF-26).
    pub default_locale: String,
    /// Administrative, technical, data protection, or security contacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<Contact>,
}

/// Contact information for an organization role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Contact {
    /// Role of this contact.
    pub role: ContactRole,
    /// Full name of the contact person or organizational unit.
    pub name: String,
    /// Contact email address.
    pub email: String,
    /// Optional contact telephone number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}

impl Contact {
    /// Creates a new contact with required role, name, and email.
    pub fn new(role: ContactRole, name: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            role,
            name: name.into(),
            email: email.into(),
            phone: None,
        }
    }
}

/// Functional responsibility of an organization contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ContactRole {
    /// Administrative contact.
    Administrative,
    /// Technical contact.
    Technical,
    /// Data protection officer / GDPR contact.
    DataProtection,
    /// Information security officer contact.
    Security,
}

impl Kind for OrganizationSpec {
    const KIND: &'static str = "Organization";
    const PLURAL: &'static str = "organizations";
    const SCOPE: Scope = Scope::Organization;

    fn validate_spec(&self, _meta: &ObjectMeta) -> Result<()> {
        self.validate()
    }

    fn repo_path(&self, _meta: &ObjectMeta) -> String {
        "org.yaml".to_string()
    }
}

impl OrganizationSpec {
    /// Validates domain name, locale preferences, and contact details (PF-25, PF-41).
    pub fn validate(&self) -> Result<()> {
        names::validate_org_domain(&self.domain)?;
        envelope::validate_locales(&self.locales, &self.default_locale)?;

        for contact in &self.contacts {
            if contact.name.trim().is_empty() {
                return Err(Error::Name {
                    field: "contacts.name",
                    value: contact.name.clone(),
                    reason: "contact name must not be empty",
                });
            }

            // ponytail: we validate e-mail with a pragmatic check (exactly one '@', non-empty local
            // part, valid org domain). Full RFC 5322 compliance is handled upstream by Keycloak
            // when verifying real user and service account addresses.
            let parts: Vec<&str> = contact.email.split('@').collect();
            if parts.len() != 2 || parts[0].is_empty() {
                return Err(Error::Name {
                    field: "contacts.email",
                    value: contact.email.clone(),
                    reason: "contact email must have exactly one `@` and a non-empty local part",
                });
            }
            names::validate_org_domain(parts[1]).map_err(|e| match e {
                Error::Name { reason, .. } => Error::Name {
                    field: "contacts.email",
                    value: contact.email.clone(),
                    reason,
                },
                other => other,
            })?;
        }

        Ok(())
    }

    /// Mints a deterministic entity URN in this organization's verified domain (PF-42, PF-44).
    pub fn urn(&self, entity_type: &str, space: &str, local_id: &str) -> Result<Urn> {
        Urn::new(entity_type, &self.domain, space, local_id)
    }
}
