//! Writes the draft-07 JSON Schema of every manifest kind to `schemas/kinds/` (T-0122, MF-09, CC-12, DM-03).
//!
//! Usage: `cargo run -p jc-core --bin export_schemas [outdir]` (default `schemas/kinds`).

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let out: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "schemas/kinds".to_string())
        .into();
    std::fs::create_dir_all(&out)?;

    for info in jc_core::registry::KINDS {
        let schema =
            jc_core::registry::schema_of(info.kind).expect("every catalogued kind has a schema");
        let mut json = serde_json::to_string_pretty(&schema)?;
        json.push('\n');
        let path = out.join(format!("{}.json", info.kind));
        std::fs::write(&path, json)?;
        println!("{}", path.display());
    }
    Ok(())
}
