//! SQL-level integration tests: LOAD the built `.duckdb_extension` into a real
//! in-memory DuckDB and exercise the full function surface (11 scalars across
//! CBOR / MessagePack / COSE).
//!
//! Run: `cargo test --release` (after `make release` + `append_metadata`).
//!
//! Bundled test DuckDB is v1.1.0: `x'..'` BLOB literals and `to_blob()` are
//! v2-only, so every test vector is built with `from_hex()` / `CAST(...)`.
//! Struct `-> 'field'` returns a JSON-typed value on v1.1.0 (quoted render),
//! so STRUCT field assertions CAST to VARCHAR and match the exact rendering.

use quack_rs::testing::InMemoryDb;

fn db() -> InMemoryDb {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/release/cbor.duckdb_extension");
    assert!(path.exists(), "build first: make release -> {path:?}");
    let d = InMemoryDb::open_unsigned().expect("open in-memory db");
    d.execute_batch(&format!("LOAD '{}'", path.display())).expect("load extension");
    d
}

/// `83010203` = CBOR array [1, 2, 3].
const ARR3: &str = "83010203";
/// `a1616101` = CBOR map {"a": 1}.
const MAP_A: &str = "a1616101";
/// `c11a514b67b0` = CBOR tag(1, 1363896240) — an epoch timestamp.
const TAG1: &str = "c11a514b67b0";
/// `830102` = truncated array (well-formed prefix, incomplete item).
const TRUNC: &str = "830102";
/// MessagePack array [1, 2, 3] (fixarray, 3 fixints).
const MP_ARR3: &str = "93010203";

#[test]
fn to_json_array_and_map() {
    let d = db();
    let arr: String = d
        .query_one(&format!("SELECT cbor_to_json(from_hex('{ARR3}'))"))
        .unwrap();
    assert_eq!(arr, "[1,2,3]");
    let m: String = d
        .query_one(&format!("SELECT cbor_to_json(from_hex('{MAP_A}'))"))
        .unwrap();
    assert_eq!(m, "{\"a\":1}");
}

#[test]
fn diagnostic_preserves_tag() {
    let d = db();
    let edn: String = d
        .query_one(&format!("SELECT cbor_diagnostic(from_hex('{TAG1}'))"))
        .unwrap();
    assert_eq!(edn, "1(1363896240)");
}

#[test]
fn is_valid_total() {
    let d = db();
    let ok: bool = d
        .query_one(&format!("SELECT cbor_is_valid(from_hex('{ARR3}'))"))
        .unwrap();
    assert!(ok);
    let bad: bool = d
        .query_one(&format!("SELECT cbor_is_valid(from_hex('{TRUNC}'))"))
        .unwrap();
    assert!(!bad, "truncated item must not be exactly one well-formed item");
}

#[test]
fn well_formed_struct() {
    let d = db();
    // Struct -> 'field' renders JSON-typed on v1.1.0; CAST to VARCHAR for an
    // exact-match assertion on the rendering.
    let ok: String = d
        .query_one(&format!(
            "SELECT CAST(cbor_well_formed(from_hex('{ARR3}')) -> 'ok' AS VARCHAR)"
        ))
        .unwrap();
    assert_eq!(ok, "true");
    let kind: Option<String> = d
        .query_one(&format!(
            "SELECT CAST(cbor_well_formed(from_hex('{ARR3}')) -> 'kind' AS VARCHAR)"
        ))
        .unwrap();
    assert_eq!(kind, Some("null".to_string()));
    // The truncated blob fails with the 'truncated' taxonomy label.
    let ok2: String = d
        .query_one(&format!(
            "SELECT CAST(cbor_well_formed(from_hex('{TRUNC}')) -> 'ok' AS VARCHAR)"
        ))
        .unwrap();
    assert_eq!(ok2, "false");
    let kind2: String = d
        .query_one(&format!(
            "SELECT CAST(cbor_well_formed(from_hex('{TRUNC}')) -> 'kind' AS VARCHAR)"
        ))
        .unwrap();
    assert_eq!(kind2, "\"truncated\"");
}

#[test]
fn untag_projects_tag_value() {
    let d = db();
    let v: String = d
        .query_one(&format!("SELECT cbor_untag(from_hex('{TAG1}'), 1)"))
        .unwrap();
    assert_eq!(v, "[1363896240]");
    // Absent tag -> empty array (not NULL).
    let none: String = d
        .query_one(&format!("SELECT cbor_untag(from_hex('{ARR3}'), 99)"))
        .unwrap();
    assert_eq!(none, "[]");
    // NULL blob -> NULL.
    let n: Option<String> = d
        .query_one("SELECT cbor_untag(CAST(NULL AS BLOB), 1)")
        .unwrap();
    assert!(n.is_none());
}

#[test]
fn from_json_roundtrips() {
    let d = db();
    let hex: String = d
        .query_one("SELECT to_hex(cbor_from_json('[1,2,3]'))")
        .unwrap();
    assert_eq!(hex.to_uppercase(), ARR3);
    // Decode back: lossless for JSON-representable shapes.
    let back: String = d
        .query_one("SELECT cbor_to_json(cbor_from_json('{\"a\":1,\"b\":[true,null]}'))")
        .unwrap();
    assert!(back.contains("\"a\":1"));
    assert!(back.contains("\"b\":["));
    // Malformed JSON -> NULL (total, never an error).
    let n: Option<String> = d
        .query_one("SELECT to_hex(cbor_from_json('{bad json'))")
        .unwrap();
    assert!(n.is_none());
}

#[test]
fn canonical_idempotent() {
    let d = db();
    let once: String = d
        .query_one(&format!(
            "SELECT to_hex(cbor_canonical(from_hex('{MAP_A}'), 'core'))"
        ))
        .unwrap();
    let twice: String = d
        .query_one(&format!(
            "SELECT to_hex(cbor_canonical(cbor_canonical(from_hex('{MAP_A}'), 'core'), 'core'))"
        ))
        .unwrap();
    assert_eq!(once.to_uppercase(), MAP_A.to_uppercase());
    assert_eq!(once, twice, "canonical re-encoding is idempotent");
}

#[test]
fn canonical_bad_mode_is_error() {
    let d = db();
    let err = d
        .query_one::<String>(&format!(
            "SELECT to_hex(cbor_canonical(from_hex('{ARR3}'), 'bogus'))"
        ))
        .expect_err("unknown canonical mode must be a SQL error, not NULL");
    assert!(err.to_string().to_lowercase().contains("mode"), "{err}");
}

#[test]
fn msgpack_transcode_roundtrip() {
    let d = db();
    // msgpack -> cbor -> json equals the direct msgpack -> json.
    let via_cbor: String = d
        .query_one(&format!(
            "SELECT cbor_to_json(msgpack_to_cbor(from_hex('{MP_ARR3}')))"
        ))
        .unwrap();
    assert_eq!(via_cbor, "[1,2,3]");
    let direct: String = d
        .query_one(&format!("SELECT msgpack_to_json(from_hex('{MP_ARR3}'))"))
        .unwrap();
    assert_eq!(direct, "[1,2,3]");
}

#[test]
fn null_and_malformed_flow_to_null() {
    let d = db();
    for q in [
        "SELECT cbor_to_json(CAST(NULL AS BLOB))",
        "SELECT cbor_diagnostic(CAST(NULL AS BLOB))",
        "SELECT cbor_is_valid(CAST(NULL AS BLOB))",
        "SELECT cbor_well_formed(CAST(NULL AS BLOB))",
        "SELECT cbor_canonical(CAST(NULL AS BLOB), 'core')",
        "SELECT cbor_cose_payload(CAST(NULL AS BLOB))",
        "SELECT cbor_cose_x5t(CAST(NULL AS BLOB))",
        "SELECT msgpack_to_json(CAST(NULL AS BLOB))",
        "SELECT msgpack_to_cbor(CAST(NULL AS BLOB))",
        "SELECT cbor_to_json(from_hex('830102'))",  // truncated
        "SELECT cbor_untag(from_hex('830102'), 1)",  // truncated
    ] {
        let v: Option<String> = d.query_one(q).unwrap_or_else(|e| panic!("{q}: {e}"));
        assert!(v.is_none(), "{q} must be NULL");
    }
}

#[test]
fn cose_payload_and_x5t_on_non_cose() {
    let d = db();
    // A plain array is not a COSE message -> NULL, not an error.
    let p: Option<String> = d
        .query_one(&format!("SELECT to_hex(cbor_cose_payload(from_hex('{ARR3}')))"))
        .unwrap();
    assert!(p.is_none());
    let x: Option<String> = d
        .query_one(&format!("SELECT cbor_cose_x5t(from_hex('{ARR3}'))"))
        .unwrap();
    assert!(x.is_none());
}
