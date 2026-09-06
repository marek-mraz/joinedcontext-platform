//! T-0110: MultiLanguageMap locale validation and resolution (PF-24, PF-25, PF-26, PF-28).

use jc_core::{Error, MultiLanguageMap};

fn map(pairs: &[(&str, &str)]) -> MultiLanguageMap {
    let mut m = MultiLanguageMap::new();
    for (l, t) in pairs {
        m.insert(l, *t).expect("test fixture uses valid locales");
    }
    m
}

fn prefs(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn the_first_matching_preferred_locale_wins() {
    let m = map(&[("sk", "Ovzdušie"), ("en", "Air quality"), ("de", "Luft")]);
    assert_eq!(m.resolve(&prefs(&["de", "en"]), "sk"), "Luft");
    assert_eq!(m.resolve(&prefs(&["en", "de"]), "sk"), "Air quality");
}

#[test]
fn a_missed_preference_falls_back_to_the_organization_default() {
    let m = map(&[("sk", "Ovzdušie"), ("en", "Air quality")]);
    assert_eq!(m.resolve(&prefs(&["fr", "it"]), "sk"), "Ovzdušie");
}

#[test]
fn a_missed_fallback_resolves_deterministically_to_the_first_key() {
    let m = map(&[("en", "Air quality"), ("de", "Luft")]);
    // BTreeMap order: de < en, so the answer is stable across runs.
    assert_eq!(m.resolve(&prefs(&["fr"]), "sk"), "Luft");
    assert_eq!(m.resolve(&[], "sk"), "Luft");
}

#[test]
fn an_empty_map_resolves_to_the_empty_string_and_never_panics() {
    let m = MultiLanguageMap::new();
    assert!(m.is_empty());
    assert_eq!(m.resolve(&prefs(&["sk", "en"]), "sk"), "");
}

#[test]
fn insert_rejects_anything_that_is_not_iso_639_1() {
    let mut m = MultiLanguageMap::new();
    for bad in ["eng", "SK", "s", "sk-SK", "", "s1", "sk "] {
        assert_eq!(
            m.insert(bad, "x"),
            Err(Error::Locale(bad.to_string())),
            "`{bad}` must be rejected"
        );
    }
    assert!(m.is_empty());
}

#[test]
fn deserialization_rejects_a_bad_language_key() {
    let ok: MultiLanguageMap =
        serde_json::from_str(r#"{"sk":"Ovzdušie","en":"Air quality"}"#).expect("valid locales");
    assert_eq!(ok.len(), 2);
    for bad in [
        r#"{"eng":"x"}"#,
        r#"{"SK":"x"}"#,
        r#"{"sk-SK":"x"}"#,
        r#"{"":"x"}"#,
    ] {
        assert!(
            serde_json::from_str::<MultiLanguageMap>(bad).is_err(),
            "`{bad}` must fail to deserialize"
        );
    }
}

#[test]
fn serialization_round_trips_and_keeps_sorted_order() {
    let m = map(&[("sk", "Ovzdušie"), ("en", "Air quality")]);
    let json = serde_json::to_string(&m).expect("serialize");
    assert_eq!(json, r#"{"en":"Air quality","sk":"Ovzdušie"}"#);
    assert_eq!(
        serde_json::from_str::<MultiLanguageMap>(&json).expect("deserialize"),
        m
    );
}

#[test]
fn require_fallback_is_the_pf26_ci_gate() {
    let m = map(&[("en", "Air quality")]);
    assert_eq!(
        m.require_fallback("sk"),
        Err(Error::MissingFallbackLocale("sk".to_string()))
    );
    assert_eq!(m.require_fallback("en"), Ok(()));
}

#[test]
fn iteration_is_sorted_and_get_is_exact() {
    let m = map(&[("sk", "a"), ("de", "b"), ("en", "c")]);
    let seen: Vec<&str> = m.iter().map(|(l, _)| l).collect();
    assert_eq!(seen, vec!["de", "en", "sk"]);
    assert_eq!(m.get("en"), Some("c"));
    assert_eq!(m.get("EN"), None);
    assert_eq!(m.get("fr"), None);
}
