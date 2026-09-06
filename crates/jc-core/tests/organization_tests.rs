use jc_core::envelope::ResourceEnvelope;
use jc_core::kinds::{ContactRole, Organization, OrganizationSpec};
use jc_core::names;

const GOLDEN: &str = r#"apiVersion: joinedcontext.com/v1alpha1
kind: Organization
metadata:
  name: banskabystrica              # DNS-1123 label, unique in the Instance
  namespace: org
  title: { sk: "Mesto Banská Bystrica", en: "City of Banská Bystrica" }
  description: { sk: "Krajské mesto", en: "Regional capital" }
spec:
  domain: banskabystrica.sk         # verified internet domain, the {orgDomain} of every URN (PF-41)
  gitRepositoryUrl: https://forge.banskabystrica.sk/mesto/config.git
  locales: [sk, en, de, cs]         # ordered, most preferred first (PF-25)
  defaultLocale: sk                 # the fallback locale, MUST be one of spec.locales (PF-25, PF-26)
  contacts:
    - role: administrative          # administrative | technical | data-protection | security
      name: "Odbor digitalizácie"
      email: digitalizacia@banskabystrica.sk
"#;

#[test]
fn golden_organization_manifest_roundtrips_and_validates() {
    let org = Organization::from_yaml(GOLDEN).expect("parse golden organization manifest");

    assert_eq!(org.metadata.name, "banskabystrica");
    assert_eq!(org.metadata.namespace.as_deref(), Some("org"));

    let title = org
        .metadata
        .title
        .as_ref()
        .expect("title should be present");
    assert_eq!(title.get("sk"), Some("Mesto Banská Bystrica"));
    assert_eq!(title.get("en"), Some("City of Banská Bystrica"));

    let desc = org
        .metadata
        .description
        .as_ref()
        .expect("description should be present");
    assert_eq!(desc.get("sk"), Some("Krajské mesto"));
    assert_eq!(desc.get("en"), Some("Regional capital"));

    assert_eq!(org.spec.domain, "banskabystrica.sk");
    assert_eq!(
        org.spec.git_repository_url.as_deref(),
        Some("https://forge.banskabystrica.sk/mesto/config.git")
    );
    assert_eq!(org.spec.locales, vec!["sk", "en", "de", "cs"]);
    assert_eq!(org.spec.default_locale, "sk");

    assert_eq!(org.spec.contacts.len(), 1);
    let contact = &org.spec.contacts[0];
    assert_eq!(contact.role, ContactRole::Administrative);
    assert_eq!(contact.name, "Odbor digitalizácie");
    assert_eq!(contact.email, "digitalizacia@banskabystrica.sk");
    assert!(contact.phone.is_none());

    org.validate().expect("envelope should validate");
    org.spec.validate().expect("spec should validate");
    assert_eq!(
        org.resource_path().expect("resource_path succeeds"),
        "org.yaml"
    );

    let serialized = org.to_yaml().expect("serialize to yaml");
    let reimported = Organization::from_yaml(&serialized).expect("deserialize serialized yaml");
    assert_eq!(org, reimported);
}

#[test]
fn organization_namespace_must_be_org() {
    let mut org = Organization::from_yaml(GOLDEN).expect("parse golden organization manifest");

    org.metadata.namespace = Some("bb".to_string());
    assert!(org.validate().is_err());

    org.metadata.namespace = None;
    assert!(org.validate().is_err());
}

#[test]
fn organization_domain_rejections() {
    let org = Organization::from_yaml(GOLDEN).expect("parse golden organization manifest");

    for bad in [
        "BanskaBystrica.sk",
        "banskabystrica.sk:443",
        "banskabystrica",
        "banskabystrica.sk/",
        "",
    ] {
        let mut spec = org.spec.clone();
        spec.domain = bad.to_string();
        assert!(
            spec.validate().is_err(),
            "expected domain `{bad}` to fail validation"
        );
    }
}

#[test]
fn organization_locales_validation_rules() {
    let org = Organization::from_yaml(GOLDEN).expect("parse golden organization manifest");

    // defaultLocale not in locales
    let mut spec1 = org.spec.clone();
    spec1.locales = vec!["sk".to_string(), "en".to_string()];
    spec1.default_locale = "fr".to_string();
    assert!(spec1.validate().is_err());

    // empty locales
    let mut spec2 = org.spec.clone();
    spec2.locales = vec![];
    assert!(spec2.validate().is_err());

    // duplicate locale
    let mut spec3 = org.spec.clone();
    spec3.locales = vec!["sk".to_string(), "sk".to_string()];
    assert!(spec3.validate().is_err());

    // invalid locale format
    let mut spec4 = org.spec.clone();
    spec4.locales = vec!["slovak".to_string()];
    assert!(spec4.validate().is_err());
}

#[test]
fn organization_mints_valid_urn_and_rejects_bad_space() {
    let org = Organization::from_yaml(GOLDEN).expect("parse golden organization manifest");

    let urn = org
        .spec
        .urn("AirQualityObserved", "ovzdusie", "station-radvan-01")
        .expect("mint urn");
    assert_eq!(
        urn.to_string(),
        "urn:ngsi-ld:AirQualityObserved:banskabystrica.sk:ovzdusie:station-radvan-01"
    );

    // illegal space name fails
    assert!(org
        .spec
        .urn(
            "AirQualityObserved",
            "Ovzdusie_Invalid",
            "station-radvan-01"
        )
        .is_err());
}

#[test]
fn organization_contact_email_must_have_at_and_valid_domain() {
    let org = Organization::from_yaml(GOLDEN).expect("parse golden organization manifest");

    let mut spec = org.spec.clone();
    spec.contacts[0].email = "invalid-email-without-at".to_string();
    assert!(spec.validate().is_err());

    spec.contacts[0].email = "@banskabystrica.sk".to_string();
    assert!(spec.validate().is_err());

    spec.contacts[0].email = "digitalizacia@invalid_domain".to_string();
    assert!(spec.validate().is_err());
}

#[test]
fn organization_spec_rejects_unknown_fields() {
    let bad_yaml = GOLDEN.replace(
        "defaultLocale: sk",
        "defaultLocale: sk\n  unexpectedField: forbidden",
    );
    assert!(Organization::from_yaml(&bad_yaml).is_err());
}

#[test]
fn organization_names_validators_smoke() {
    assert!(names::validate_org_domain("banskabystrica.sk").is_ok());
    assert!(names::validate_locale("sk").is_ok());
    assert!(ResourceEnvelope::<OrganizationSpec>::new(
        org_meta(),
        OrganizationSpec {
            domain: "banskabystrica.sk".to_string(),
            git_repository_url: None,
            locales: vec!["sk".to_string()],
            default_locale: "sk".to_string(),
            contacts: vec![],
        }
    )
    .resource_path()
    .is_ok());
}

fn org_meta() -> jc_core::ObjectMeta {
    jc_core::ObjectMeta::new("banskabystrica", "org")
}
