# duckdb-cbor

**CBOR (RFC 8949) + MessagePack, in SQL.** Decode, validate, canonicalize,
tag-project, and transcode binary self-describing data right where you query it
— with first-class COSE payload/thumbprint extraction for JWS/CWT/WebAuthn
workflows. The lossless JSON projection for CBOR, EDN for the debug view.

Built as a DuckDB loadable extension with the [quack-rs](https://crates.io/crates/quack-rs)
C-API binding layer. The engine (`cbor_core/`) is a verbatim port of the
[Query-farm `vgi-cbor` cbor-core crate](https://github.com/Query-farm/vgi-cbor)
(MIT/Apache-2.0) — a pure-Rust structural decoder with **no Arrow, no VGI, no
cryptographic verification**; only the transport layer was replaced with direct
C-API vector I/O.

## Functions (v1)

| Function | Signature | Returns |
|---|---|---|
| `cbor_to_json` | `(blob)` | VARCHAR — canonical JSON (byte strings as base64url) |
| `cbor_diagnostic` | `(blob)` | VARCHAR — RFC 8949 §8 Extended Diagnostic Notation |
| `cbor_is_valid` | `(blob)` | BOOLEAN — exactly one well-formed item, no trailing bytes |
| `cbor_well_formed` | `(blob)` | STRUCT(ok BOOLEAN, error VARCHAR, kind VARCHAR) |
| `cbor_untag` | `(blob, tag UBIGINT)` | VARCHAR — JSON array of values under a semantic tag |
| `cbor_from_json` | `(json VARCHAR)` | BLOB — JSON text → core-deterministic CBOR |
| `cbor_canonical` | `(blob, mode VARCHAR)` | BLOB — deterministic re-encode (`core` \| `ctap2`) |
| `cbor_cose_payload` | `(blob)` | BLOB — COSE inner payload (tagged or unprotected) |
| `cbor_cose_x5t` | `(blob)` | VARCHAR — COSE x5t thumbprint (lowercase hex) |
| `msgpack_to_json` | `(blob)` | VARCHAR — MessagePack → JSON (ext/timestamp handled) |
| `msgpack_to_cbor` | `(blob)` | BLOB — MessagePack → CBOR transcode |

`kind` taxonomy from `cbor_well_formed`: `truncated`, `trailing_bytes`,
`duplicate_keys`, `nesting_depth`, `unknown_tag_policy`, …

## Try it

```sql
LOAD 'cbor.duckdb_extension';

-- Decode: lossless JSON projection.
SELECT cbor_to_json(from_hex('83010203'));      -- [1,2,3]
SELECT cbor_to_json(from_hex('a1616101'));      -- {"a":1}
-- Debug view: keeps tags, byte strings, the null/undefined distinction.
SELECT cbor_diagnostic(from_hex('c11a514b67b0'));  -- 1(1363896240)
-- Validate: total, per-row, never aborts.
SELECT cbor_is_valid(from_hex('830102'));      -- false (truncated)
SELECT cbor_well_formed(from_hex('830102'));   -- {ok: false, error: 'input ended…', kind: 'truncated'}
-- Tag projection: pull the value(s) under a semantic tag.
SELECT cbor_untag(from_hex('c11a514b67b0'), 1);  -- [1363896240]
-- Encode: JSON → core-deterministic CBOR bytes.
SELECT to_hex(cbor_from_json('[1,2,3]'));      -- 83010203
-- Canonicalize: RFC 8949 §4.2.1 (core) or CTAP2, idempotent.
SELECT to_hex(cbor_canonical(from_hex('a1616101'), 'core'));
-- Cross-format: MessagePack → CBOR, then read back as JSON.
SELECT cbor_to_json(msgpack_to_cbor(from_hex('93010203')));  -- [1,2,3]
-- COSE: the JWS/CWT/WebAuthn join key.
SELECT cbor_cose_payload(cose_bytes), cbor_cose_x5t(cose_bytes);
```

## Semantics

- **NULL flows through**: NULL blob / NULL json → NULL result.
- **Malformed input → NULL** (the decoders are total and bound recursion at a
  fixed max nesting depth, so a hostile blob fails its own row, never crashes
  the scan). The one exception: `cbor_canonical` with an unknown `mode` is a
  caller mistake → clean SQL error.
- **`mode`/`tag` are regular arguments**: DuckDB broadcasts a literal into the
  vector, so `cbor_untag(blob, 1)` works with signature `cbor_untag(BLOB,
  UBIGINT)`. (The source worker used a scalar bind callback for constants, but
  that API requires DuckDB 1.5+; the bundled test harness is v1.1.0.)
- **`x5t` is lowercase hex** of the thumbprint bytes (the join key to an x509
  catalog), not base64url as in the JWS header.

## Deferred (v2 — binding surface growth)

- `cbor_tags` → `LIST<STRUCT(tag, path, value)>` (all tags, document order)
- `cbor_encode` (any DuckDB type → CBOR), `msgpack_encode`, `msgpack_decode`
- `cbor_decode` (alias of `cbor_to_json` in the source; the mode argument is a
  v1 no-op — a DuckDB scalar fixes its output type at bind with no data sample)
- `cwt_claims` (STRUCT), `cose_headers` / `cose_key` / `cose_x5chain`
  (nested STRUCT/LIST)
- `webauthn_attestation`, `seq_decode` (table functions)

All deferred surfaces are available in the `cbor_core/` engine; only the quack-rs
binding is outstanding.

## Build

```bash
cargo build --release
cargo run --bin append_metadata --release \
  -- target/release/libcbor.so target/release/cbor.duckdb_extension
cargo test --release --test integration   # compiles a bundled in-memory DuckDB
```

CI builds linux_amd64 / linux_arm64 / osx_amd64 / osx_arm64 / windows_amd64
via `extension-ci-tools`.

## Dependencies

| crate | role |
|---|---|
| `ciborium 0.2` | CBOR (RFC 8949) codec + dynamic Value + tags |
| `rmpv 1.3` | MessagePack dynamic Value |
| `serde_json` | JSON projection |
| `uuid` | AAGUID normalization (WebAuthn) |
| `hex` / `base64` | encodings for x5t / JSON byte-strings |

## License

MIT OR Apache-2.0 (engine ported from Query-farm vgi-cbor, MIT).
