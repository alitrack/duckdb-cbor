// DuckDB loadable extension: CBOR (RFC 8949) + MessagePack codec, validation,
// canonicalization, semantic-tag projection, and COSE payload extraction.
//
// Thin quack-rs binding layer over `cbor_core` (verbatim from Query-farm's
// vgi-cbor `cbor-core` crate, MIT/Apache-2.0 — a pure-Rust structural decoder
// with no Arrow/VGI dependency; only the transport layer was replaced with
// direct C-API vector I/O).
//
// Function surface (v1 — flat VARCHAR/BLOB/BOOLEAN/STRUCT returns):
//
//   cbor_to_json(blob)            -> VARCHAR  canonical JSON (byte strings base64url)
//   cbor_diagnostic(blob)         -> VARCHAR  RFC 8949 Extended Diagnostic Notation
//   cbor_is_valid(blob)           -> BOOLEAN  exactly one well-formed CBOR item
//   cbor_well_formed(blob)        -> STRUCT(ok BOOLEAN, error VARCHAR, kind VARCHAR)
//   cbor_untag(blob, tag)         -> VARCHAR  JSON array of values under a tag
//   cbor_from_json(json)          -> BLOB     JSON text -> core-deterministic CBOR
//   cbor_canonical(blob, mode)    -> BLOB     re-encode deterministically (core|ctap2)
//   cbor_cose_payload(blob)       -> BLOB     COSE payload (tagged or unprotected)
//   cbor_cose_x5t(blob)           -> VARCHAR  COSE x5t22519/x5t256 base64url thumbprint
//   msgpack_to_json(blob)         -> VARCHAR  MessagePack -> JSON
//   msgpack_to_cbor(blob)         -> BLOB     MessagePack -> CBOR transcode
//
// Semantics (inherited from vgi-cbor):
//   * NULL blob / NULL json -> NULL result (missing data flows through).
//   * Malformed input -> NULL (the decoders are total; dirty data never
//     aborts a query). The one exception: `cbor_canonical` with an unknown
//     `mode` value is a caller mistake -> clean SQL error.
//   * `mode`/`tag` are passed as regular arguments: DuckDB broadcasts a
//     literal into the vector, so `cbor_untag(blob, 1)` works while the
//     signature stays `cbor_untag(BLOB, UBIGINT)` (no scalar-bind feature,
//     which requires DuckDB 1.5+; the bundled test harness is v1.1.0).
//
// Deferred (documented in README, added when the binding surface grows):
//   cbor_tags (LIST<STRUCT>), cbor_encode (any DuckDB type -> CBOR),
//   msgpack_encode, msgpack_decode, cbor_decode, cwt_claims, cose_headers,
//   cose_key, cose_x5chain, webauthn_attestation + seq_decode (tables).

use quack_rs::connection::{Connection, Registrar};
use quack_rs::error::ExtensionError;
use quack_rs::scalar::{ScalarFunctionBuilder, ScalarFunctionInfo};
use quack_rs::types::{LogicalType, TypeId};
use quack_rs::vector::{StructWriter, VectorReader, VectorWriter};

use cbor_core::codec::{diagnostic, encode, json, msgpack, tags};
use cbor_core::security::cose;
use cbor_core::validate;

const WELL_FORMED_FIELDS: &[(&str, TypeId)] = &[
    ("ok", TypeId::Boolean),
    ("error", TypeId::Varchar),
    ("kind", TypeId::Varchar),
];

// ─────────────────────────────────────────────────────────────────────────────
// cbor_to_json(blob) -> VARCHAR
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(cbor_to_json_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            if !blob.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            match json::to_json_string(blob.read_blob(row)) {
                Ok(s) => writer.write_varchar(row, &s),
                Err(_) => writer.set_null(row), // malformed -> NULL
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// cbor_diagnostic(blob) -> VARCHAR
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(cbor_diagnostic_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            if !blob.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            match diagnostic::diagnostic(blob.read_blob(row)) {
                Ok(s) => writer.write_varchar(row, &s),
                Err(_) => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// cbor_is_valid(blob) -> BOOLEAN
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(cbor_is_valid_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            if !blob.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            writer.write_bool(row, validate::is_valid(blob.read_blob(row)));
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// cbor_well_formed(blob) -> STRUCT(ok BOOLEAN, error VARCHAR, kind VARCHAR)
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(cbor_well_formed_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut sw = StructWriter::new(output, WELL_FORMED_FIELDS.len());
        for row in 0..row_count {
            if !blob.is_valid(row) {
                sw.set_row_null(row);
                continue;
            }
            let wf = validate::well_formed(blob.read_blob(row));
            sw.write_bool(row, 0, wf.ok);
            match &wf.error {
                Some(e) => sw.write_varchar(row, 1, e),
                None => sw.set_null(row, 1),
            }
            match &wf.kind {
                Some(k) => sw.write_varchar(row, 2, k),
                None => sw.set_null(row, 2),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// cbor_untag(blob, tag) -> VARCHAR   (JSON array of values under `tag`)
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(cbor_untag_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let tag = VectorReader::new(input, 1);
        let row_count = blob.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            if !blob.is_valid(row) || !tag.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            match tags::untag(blob.read_blob(row), tag.read_i64(row) as u64) {
                Ok(s) => writer.write_varchar(row, &s),
                Err(_) => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// cbor_from_json(json) -> BLOB
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(cbor_from_json_fn, |_info, input, output| {
    unsafe {
        let json_col = VectorReader::new(input, 0);
        let row_count = json_col.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            if !json_col.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            match json::from_json_str(json_col.read_str(row)) {
                Ok(b) => writer.write_blob(row, &b),
                Err(_) => writer.set_null(row), // malformed JSON -> NULL
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// cbor_canonical(blob, mode) -> BLOB   (mode: 'core' | 'ctap2'; unknown -> error)
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(cbor_canonical_fn, |info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let mode = VectorReader::new(input, 1);
        let row_count = blob.row_count();
        let mut writer = VectorWriter::new(output);
        let fn_info = ScalarFunctionInfo::new(info);
        for row in 0..row_count {
            if !blob.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            let canon = if mode.is_valid(row) {
                match encode::Canon::parse(mode.read_str(row)) {
                    Ok(c) => c,
                    Err(e) => {
                        fn_info.set_error(&e);
                        return;
                    }
                }
            } else {
                encode::Canon::Core
            };
            match encode::canonical(blob.read_blob(row), canon) {
                Ok(b) => writer.write_blob(row, &b),
                Err(_) => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// cbor_cose_payload(blob) -> BLOB
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(cbor_cose_payload_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            if !blob.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            match cose::cose_payload(blob.read_blob(row)) {
                Ok(Some(b)) => writer.write_blob(row, &b),
                _ => writer.set_null(row), // not COSE / no payload -> NULL
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// cbor_cose_x5t(blob) -> VARCHAR
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(cbor_cose_x5t_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            if !blob.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            match cose::cose_x5t(blob.read_blob(row)) {
                Ok(Some(s)) => writer.write_varchar(row, &s),
                _ => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// msgpack_to_json(blob) -> VARCHAR
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(msgpack_to_json_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            if !blob.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            match msgpack::to_json_string(blob.read_blob(row)) {
                Ok(s) => writer.write_varchar(row, &s),
                Err(_) => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// msgpack_to_cbor(blob) -> BLOB
// ─────────────────────────────────────────────────────────────────────────────

quack_rs::scalar_callback!(msgpack_to_cbor_fn, |_info, input, output| {
    unsafe {
        let blob = VectorReader::new(input, 0);
        let row_count = blob.row_count();
        let mut writer = VectorWriter::new(output);
        for row in 0..row_count {
            if !blob.is_valid(row) {
                writer.set_null(row);
                continue;
            }
            match msgpack::to_cbor(blob.read_blob(row)) {
                Ok(b) => writer.write_blob(row, &b),
                Err(_) => writer.set_null(row),
            }
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Registration + entry point
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    con.register_scalar(
        ScalarFunctionBuilder::new("cbor_to_json")
            .param(TypeId::Blob)
            .returns(TypeId::Varchar)
            .function(cbor_to_json_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("cbor_diagnostic")
            .param(TypeId::Blob)
            .returns(TypeId::Varchar)
            .function(cbor_diagnostic_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("cbor_is_valid")
            .param(TypeId::Blob)
            .returns(TypeId::Boolean)
            .function(cbor_is_valid_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("cbor_well_formed")
            .param(TypeId::Blob)
            .returns_logical(LogicalType::struct_type(WELL_FORMED_FIELDS))
            .function(cbor_well_formed_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("cbor_untag")
            .param(TypeId::Blob)
            .param(TypeId::UBigInt)
            .returns(TypeId::Varchar)
            .function(cbor_untag_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("cbor_from_json")
            .param(TypeId::Varchar)
            .returns(TypeId::Blob)
            .function(cbor_from_json_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("cbor_canonical")
            .param(TypeId::Blob)
            .param(TypeId::Varchar)
            .returns(TypeId::Blob)
            .function(cbor_canonical_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("cbor_cose_payload")
            .param(TypeId::Blob)
            .returns(TypeId::Blob)
            .function(cbor_cose_payload_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("cbor_cose_x5t")
            .param(TypeId::Blob)
            .returns(TypeId::Varchar)
            .function(cbor_cose_x5t_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("msgpack_to_json")
            .param(TypeId::Blob)
            .returns(TypeId::Varchar)
            .function(msgpack_to_json_fn),
    )?;

    con.register_scalar(
        ScalarFunctionBuilder::new("msgpack_to_cbor")
            .param(TypeId::Blob)
            .returns(TypeId::Blob)
            .function(msgpack_to_cbor_fn),
    )?;

    Ok(())
}

quack_rs::entry_point_v2!(cbor_init_c_api, |con| register_all(con));
