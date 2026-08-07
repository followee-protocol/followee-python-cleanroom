# Authoring Record: Followee Python Clean-Room Model

Author: clean-room authoring session (Claude Code), 2026-08-05.
Inputs: exactly the two approved files listed in `AUTHORING-CONSTRAINTS.md`,
verified by SHA-256 before authoring began.  No other Followee material was
inspected, searched for, or received.  No GitHub or web search was performed.

## Environment and dependencies

- Python 3.10.12 (system interpreter, Linux/WSL2).
- **No third-party dependencies.**  Only Python standard-library modules are
  used (`hashlib`, `re`, `enum`, `dataclasses`, `json`, `pathlib`,
  `itertools`, `typing`, `unittest`).  There is consequently no dependency
  lock file; the standard-library-only constraint is the lock.
- Tests run with the standard-library `unittest` runner:
  `python3 -m unittest discover -s tests -t .` from `tools/python-model/`.

## External standards relied upon

The specification cites its normative externals in Appendix C.  This model
was written from the author's working knowledge of those documents; no
document was fetched over the network during the session.  The standards
whose content materially shaped code are:

| Standard | Used for | URL |
| --- | --- | --- |
| RFC 8949 | CBOR encoding, deterministic-encoding rules (Section 4.2.1), well-formedness (ill-formed vs invalid items, reserved additional-info values, two-byte simple-value floor of 32) | https://www.rfc-editor.org/rfc/rfc8949 |
| RFC 9052 | COSE Sign1 structure and `Sig_structure` layout (`"Signature1"`, protected bytes, external AAD, payload) | https://www.rfc-editor.org/rfc/rfc9052 |
| RFC 8032 | Ed25519: key generation, signing, point decompression (Section 5.1.3), verification equation, Section 7.1 test vectors (reproduced from memory in `tests/test_ed25519.py` and independently confirmed by matching all Appendix B signatures) | https://www.rfc-editor.org/rfc/rfc8032 |
| RFC 3986 | `absolute-URI` grammar (scheme, hier-part, authority, IPv6/IPvFuture literals, pchar, query) | https://www.rfc-editor.org/rfc/rfc3986 |
| RFC 6838 | `restricted-name` grammar for `mediaType` (Section 4.2: leading alphanumeric, chars `!#$&-^_.+`, 127-char name cap) | https://www.rfc-editor.org/rfc/rfc6838 |
| RFC 5646 | `Language-Tag` ABNF including the fixed irregular and regular grandfathered lists; case-insensitive well-formedness | https://www.rfc-editor.org/rfc/rfc5646 |
| RFC 8288 | `reg-rel-type` grammar for `rel` tokens | https://www.rfc-editor.org/rfc/rfc8288 |
| RFC 9864 | Only the fact that COSE `alg` `-19` is fully-specified Ed25519; the numeric value itself is given by the Followee specification | https://www.rfc-editor.org/rfc/rfc9864 |
| multiformats multibase/multicodec | Base58btc alphabet and `z` prefix; unsigned-varint convention including its 9-byte practical maximum | https://github.com/multiformats/multibase, https://github.com/multiformats/unsigned-varint |

The Ed25519 group constants (p, L, d, base point y = 4/5) are the RFC 8032
domain parameters.  The strictness checks beyond RFC 8032 (S < L, subgroup
membership via [L]P = identity, non-identity public key, uncofactored
equation) implement Followee Section 3.3 items 1-7 directly.

## Interpretation decisions and ambiguities

Recorded rather than resolved against any other implementation, per the
clean-room procedure.  Numbers refer to the specification.

1. **"Absolute URI" and fragments (7.2).**  The spec requires URI fields to
   be "an absolute URI under RFC 3986" and says "relative references are
   malformed."  RFC 3986's `absolute-URI` production excludes fragments,
   while the contrast drawn ("relative references") could suggest only the
   scheme requirement was intended.  **Chosen:** the literal `absolute-URI`
   production — a fragment (`...#x`) makes the field malformed.  Flagged as
   a likely differential-test divergence point.
   *Resolved by specification v0.7*, which pins the RFC 3986 `URI`
   production (fragments and queries permitted); see the v0.7 maintenance
   section below.
2. **Error classification under multiple failures (8.1).**  The permitted
   reordering of "cheap independent checks" with an "equivalent" final
   result leaves the reported *code* ambiguous when several checks would
   fail.  **Chosen:** perform the numbered steps of Section 8.1 exactly in
   the listed order and report the first failure.  Consequences include:
   binding mismatches (steps 7/9) are reported even when the signature is
   also invalid, and Contact Document violations (step 15) are reported
   only after signature verification (step 14) succeeds.
3. **Protected-header mismatch classification (6.2, 15.3).**  A protected
   map of exactly `{1: <int != -19>}` reports `unsupportedSuite`
   (Section 3.2: `-8` "MUST NOT be accepted", unsupported suites produce
   `unsupportedSuite`).  Any other deviation from the exact bytes `a10132`
   (extra entries, wrong types, undecodable content) is `schemaViolation`.
4. **Descriptor version other than 1 (4.1).**  No dedicated error code
   exists; classified `schemaViolation` (CDDL pins `0: 1`).
5. **Revealed revocation key with wrong suite or key length (5.1, 15.3).**
   Classified `invalidRevocationKey`, following the code-8 description
   "does not match the commitment or key profile".  Structural failures of
   the label-5 map (wrong label set, non-map) are `schemaViolation`.
6. **Invalid UTF-8 in a text string (6.1 item 8).**  Classified
   `nonDeterministicCbor` (a Section 6.1 profile violation), not
   `invalidCbor`.
   *Resolved by specification v0.8*, which moves UTF-8 validity (and
   duplicate map keys) into RFC 8949 basic validity and assigns
   `invalidCbor`; see the v0.8 maintenance section below.
7. **Unassigned CBOR simple values.**  Not mentioned by Section 6.1; no
   Followee schema admits them.  Well-formed unassigned simple values are
   rejected as `nonDeterministicCbor`; the ill-formed two-byte form with
   value < 32 is `invalidCbor` per RFC 8949.
   *Revised under specification v0.8*: the layered classification places
   well-formed unassigned simple values past Sections 6.1.1 and 6.1.2, so
   they now classify as `schemaViolation`; see the v0.8 maintenance
   section below.
8. **Multihash varint bound (3.1).**  Unsigned varints are capped at
   9 bytes per the multiformats convention; longer varints produce
   `invalidDid` as structurally malformed.
9. **Detached payload (6.2, B.7 item 6).**  A `nil` payload violates the
   required profile: `schemaViolation`.
10. **Malformed DID inside `migration` (7.4).**  `invalidDid` is reserved
    for the requested/target DID; a non-canonical DID string inside the
    Contact Document is a schema failure of that document:
    `schemaViolation`.  Migration DID values are required to parse under
    the full v1 profile (an `unsupportedHash`-shaped value is likewise a
    `schemaViolation` there).
11. **Depth counting (15.1).**  "Record-body CBOR nesting depth 8" is read
    as container nesting depth with the record-body map at depth 1; only
    arrays and maps add depth.
12. **Member counting (15.1).**  "Total record-body map and array members"
    counts every map entry (one per key/value pair) and every array element,
    recursively, over the record body only (the COSE envelope array and
    headers are outside it).  This reading exactly reproduces the
    specification's own arithmetic of "at most 61 minimal services in a
    Root record and 60 in a RootRevoked record"
    (12 + 4n <= 256 and 15 + 4n <= 256).
13. **Trailing bytes.**  Trailing bytes after the tagged envelope or after
    the record-body item make the input not "exactly one" CBOR item:
    `invalidCbor`.
14. **Signature length (6.2 item 6).**  A signature field that is not
    exactly 64 bytes is `schemaViolation` (CDDL `.size 64`); a 64-byte
    signature that fails cryptographic checks is `invalidSignature`.
15. **Non-minimal outer tag encoding.**  `0xd8 0x12` (tag 18 in two bytes)
    is `nonDeterministicCbor`; a different tag value is `schemaViolation`;
    a non-tag first item is `schemaViolation` ("missing tag").
16. **`rel` byte cap (7.3, 15.1).**  The 256-byte maximum applies to both
    the token form and the absolute-URI form of `rel`.
17. **Contact 12 KiB cap (15.1).**  Measured over the deterministic CBOR
    encoding of the contact map value, which equals the received bytes
    (guaranteed by strict decoding).
18. **Decoded-representation collisions.**  CBOR admits map keys the
    Python model cannot faithfully hold (`1` vs `true`, container keys).
    No v1 schema admits any of them; they are rejected at decode time as
    `schemaViolation` so no information is silently lost.
19. **Step 13 (8.1).**  With only suite `-19` in v1, the "selected key
    suite equals protected algorithm" check is vacuously true once steps
    3, 8, and 12 have pinned both sides; retained as an internal invariant.
20. **Selection outcome vocabulary.**  Per-candidate outcomes in the
    selection model reuse the wire codes symbolically: `premature`,
    `rootRevoked` (sticky exclusion), `losingRecord`, `duplicate`
    (body-digest match with the winner, Section 8.4).
21. **Identity elements (3.3).**  The identity point is rejected as a
    public key (item 5 requires non-identity) but accepted as a decoded
    `R` (item 6 requires only prime-order subgroup membership, which the
    identity satisfies).  The uncofactored equation then decides.
22. **Appendix B structured inputs.**  Treated as vector *inputs*: seeds,
    the two timestamps 1785589200123 (given in B.4) and 1785589201123
    (taken from the B.5 body bytes of the approved fixture), and the
    Contact Document field values shown in Section 9.6/B.4.  All derived
    values (keys, commitment, descriptor bytes, digest, DID, body bytes,
    Sig_structure, body digests, signatures, envelopes) are computed by
    the model and compared against the fixture in
    `tools/python-model/tests/test_appendix_b.py`.
23. **`validUntil_ms` boundaries (5.4, 5.5).**  Premature strictly greater
    (`timestamp > now + 300000`); stale strictly greater
    (`now > validUntil`); `validUntil == timestamp` is valid;
    `timestamp == now + 300000` is admissible.  All comparisons use
    Python's unbounded integers, so they are inherently overflow-safe.
24. **Empty containers.**  An empty Contact Document is valid (7.1); empty
    `alsoKnownAs`/`services` arrays and empty extension maps are accepted
    (CDDL `*`); an empty `migration` map is rejected (7.4 requires at
    least one field).
25. **Service `type` URI length.**  The generic 2,048-byte "any URI" cap
    applies to URI-form service types; no tighter bound is stated.

## Post-freeze clean-room review corrections (2026-08-05)

An independent review of the freeze revision (`7ca1f62`), derived solely
from the approved specification and the frozen Python source, reported two
defects.  No Rust source, fixtures, outputs, or other excluded or
provisional Followee material was revealed to or inspected by this session
in receiving or fixing them.

1. **Boolean CBOR labels versus fixed integer labels.**  Python evaluates
   `False == 0` and `True == 1`, so the set-equality label checks in
   `descriptor.validate_public_key()` and `descriptor.validate_descriptor()`
   accepted deterministic CBOR maps keyed by `false`/`true` in place of the
   required uint labels — including a complete, descriptor-bound, correctly
   signed envelope.  Fixed by requiring `type(label) is int` for every
   label before the set comparison.  Audit of the other fixed-label map
   checks: `record.py` (body, contact, service, migration, extension-object
   labels) already enforced exact label types; `cose._classify_protected`
   had the same aliasing flaw in its *classification* branch only (a
   boolean-keyed protected header was rejected either way but as
   `unsupportedSuite` rather than `schemaViolation`) and was corrected;
   `parse_envelope`'s empty-unprotected comparison and all value-position
   checks were already exact-type safe.  Regression tests cover `false` and
   `true` substitutions in both maps at unit level and a fully signed,
   descriptor-bound envelope with a boolean descriptor label, asserted to
   fail with `schemaViolation` while its Ed25519 signature verifies.
2. **IPvFuture case-insensitivity (RFC 3986).**  RFC ABNF string literals
   are case-insensitive, so IPvFuture's `"v"` must match `v` and `V`; the
   URI grammar previously accepted only lowercase.  Fixed to `[vV]` with
   positive tests for both forms.  The recorded `absolute-URI`/fragment
   interpretation (ambiguity 1 above) is deliberately unchanged.

## v0.7 maintenance pass (2026-08-05)

Bounded maintenance pass under the updated `AUTHORING-CONSTRAINTS.md`.

**Revisions.**
- v0.6 base model: commit `70e4a6caa8720f1dfbb3b183a5d305fca0cf3e57`
  (`cleanroom-v0.6-review1`), itself descending from the v0.6 freeze
  `7ca1f623453065deefd1e6cfdf15e135d523dd7e`.
- v0.6 specification input: `followee-protocol/followee` commit
  `44c68660f0c0a1e3504c0f9794b8c51058da6f18` (recorded in this
  repository's history at commit `70b393f`).
- v0.7 specification input: `followee-protocol/followee` commit
  `abc9a55d90f1026e6509207abda73e5dc6d14241`, SHA-256
  `2b264823ba68d9a7d69ce68de5c1408ac8a3d54ff6d726ab89ee2baa2707c81f`,
  pinned by repository commit `6b944b952d1daec6840deae7e07f304f5349637d`.
- Appendix B fixture unchanged (SHA-256
  `f188316ffd7ad07fe94a842027f1ea7596e42a2f00b0691c1096fa2bfaddb717`).

The semantic delta was determined exclusively from this repository's own
Git history (`git diff 70e4a6c..6b944b9 -- Followee-Specification.md`)
plus a full read of the v0.6 text earlier in the clean room; no other
implementation was consulted.

**Semantic differences identified (v0.6 → v0.7).**

1. *Section 7.2 URI grammar (normative behavior change).*  URI fields now
   match the RFC 3986 Section 3 `URI` production: a scheme is required and
   the optional query and fragment components are permitted; every
   `relative-ref` form (network-path, absolute-path, relative-path,
   query-only, fragment-only) is malformed.  This resolves recorded
   ambiguity 1 — in the opposite direction from the v0.6 model's chosen
   `absolute-URI` reading, so fragments change from rejected to accepted.
   Sections 5.6, 7.1, and 7.3 now phrase avatar, `alsoKnownAs` entries,
   service `type` (URI form), `endpoint`, `rel` (URI form), and extension
   keys as "URI satisfying Section 7.2".  **Code change:**
   `syntax.py` — `is_absolute_uri()` replaced by `is_uri()` with an
   optional `#fragment` component (fragment grammar `*( pchar / "/" /
   "?" )`); `record.py` call sites and messages updated.  Migration
   values are unaffected (still canonical Followee DIDs, not Section 7.2
   URIs).
2. *Section 7.2 IPvFuture case (codifies existing behavior).*  New
   paragraph: RFC ABNF string literals are case-insensitive (RFC 5234),
   so both `v` and `V` introduce IPvFuture.  The model already conformed
   via the v0.6 post-freeze review fix.  **Tests only.**
3. *Section 6.1 exact label typing plus Appendix B.7 item 17 and the
   Section 20.1 additions (codifies existing behavior).*  Integer map
   labels are CBOR major-type-0 keys; `false`/`true` MUST NOT be accepted
   as labels `0`/`1` even where the host language compares them equal,
   and key type must be enforced before host-language lookup or
   set-equality.  B.7 item 17 requires an otherwise consistent,
   descriptor-bound, correctly signed boolean-label record to fail with
   `schemaViolation`.  The model already conformed via the v0.6
   post-freeze review fix.  **Tests only.**
4. *Non-normative for this model:* version header v0.7, expanded
   Section 20.1 conformance list, new Appendix C reference to RFC 5234.
   Appendix B vectors are unchanged (fixture hash identical).

**Changes made.**

- Code: `followee_model/syntax.py` (URI production with optional
  fragment; function renamed `is_uri`), `followee_model/record.py`
  (call sites, error messages, docstring), `followee_model/__init__.py`
  (docstring version).
- Tests: `tests/test_syntax.py` (fragment/query positives including the
  Section 7.2 examples, all five relative-reference negatives, fragment
  edge cases); new `tests/test_v07_conformance.py` (one focused class per
  normative change: URI production exercised on every URI-bearing record
  field including extension keys, with the 2,048-byte cap re-checked
  across a fragment; IPvFuture `v`/`V` at unit and full-record level;
  B.7 item 17 signed-vector, nested public-key, revealed revocation-key,
  and wire-level `f4` byte cases); comment fix in
  `tests/test_verify_behavior.py`.
- Documentation: this section; ambiguity 1 annotated as resolved;
  `tools/python-model/README.md` updated to describe the v0.6 authorship
  plus v0.7 maintenance and the renamed grammar.

**Ambiguities found in the v0.7 delta.**  None new.  The delta's changed
paragraphs are prescriptive and match the model's existing
classifications (`schemaViolation` for boolean labels, including the
signed B.7 item 17 vector, as the v0.6 review corrections already chose).

**External material consulted for the v0.7 pass.**  None fetched.  The
fragment ABNF (`fragment = *( pchar / "/" / "?" )`) comes from working
knowledge of RFC 3986 (already listed above); RFC 5234's
case-insensitivity rule is restated inside the v0.7 specification text
itself.  No new dependencies were added; the model remains Python
3.10 standard-library only.

**Exclusion statement.**  No excluded or provisional Followee material
was inspected, searched for, received, or supplied during this pass: no
`followee-rs` source, tests, documentation, issues, CI output, or
history; no whitepaper; no `IMPLEMENTATION.md`, `SPEC-QUESTIONS.md`, or
`tools/spec_vector_check.py`; no implementation-status or provisional
fixtures; no Rust-derived expected outputs; no reports from another
implementation; and no GitHub or web searches for Followee material.
The only inputs were this repository at commit `6b944b9` (including its
own Git history) and the two approved files verified by SHA-256 above.

## v0.8 maintenance pass (2026-08-07)

Bounded maintenance pass under the updated `AUTHORING-CONSTRAINTS.md`,
performed in a fresh session containing only the approved inputs.

**Revisions.**
- v0.7 base model: commit `a39138dae8072c7b89dc922bcfe6f5717312c6e6`
  (`cleanroom-v0.7-maintenance-freeze`), verified before any change,
  with the freeze tag still peeling to it.
- v0.8 input-preparation commit:
  `5d00c792a8d61f7080ad3f0ccf04642b2b491017`, based directly on the v0.7
  freeze.
- v0.7 specification input (retained at the repository root):
  `followee-protocol/followee` commit
  `abc9a55d90f1026e6509207abda73e5dc6d14241`, SHA-256
  `2b264823ba68d9a7d69ce68de5c1408ac8a3d54ff6d726ab89ee2baa2707c81f`.
- v0.8 specification input (`inputs/v0.8/Followee-Specification.md`):
  `followee-protocol/followee` commit
  `610f9a1e78d860e8bd685ef1435a53a16f1221ec`, SHA-256
  `474f0b3880e838a5232890c3e2edc183c341fd25e28d7db0066ad109aa43113b`.
- Pre-v0.8 Appendix B fixture unchanged (SHA-256
  `f188316ffd7ad07fe94a842027f1ea7596e42a2f00b0691c1096fa2bfaddb717`).
- Resulting model commit: recorded in Git as the sole child of the
  input-preparation commit (this maintenance commit).

The semantic delta was derived independently by reading both pinned
specifications completely, then cross-checked with a mechanical `diff`
of the two approved files inside this repository.  No summary,
affected-section list, rationale, expected-change checklist, or other
implementation was requested, received, or consulted.

**Semantic differences identified (v0.7 → v0.8).**

1. *Section 6.1 layered CBOR classification (normative behavior change
   for this model).*  Section 6.1 is restructured into 6.1.1
   (well-formedness and RFC 8949 basic validity: unique map keys under
   generic data-model value equivalence, RFC 3629 UTF-8, both checked
   recursively through arrays and maps and stopping at byte-string
   boundaries), 6.1.2 (the deterministic/restricted profile), and 6.1.3
   (schema, with `schemaViolation` as fallback).  Section 15.3 redefines
   `invalidCbor` (code 4) to cover not-well-formed *and* basically
   invalid input — including duplicate map keys and invalid UTF-8 — and
   `nonDeterministicCbor` (code 5) to cover basically valid input that
   violates Section 6.1.2.  Under v0.7 the model classified duplicate
   keys and invalid UTF-8 as `nonDeterministicCbor` (former Section 6.1
   rules 4 and 8; recorded interpretation 6).  **Code change:**
   `detcbor.py` reclassifies byte-identical duplicate map keys and
   invalid UTF-8 text strings to `invalidCbor`.
2. *Section 6.1.3 multi-fault rule (new normative flexibility).*  When
   one input independently violates more than one rule, the exact error
   is unspecified unless a normative rule or vector assigns precedence;
   exact error assertions require fault-isolated inputs.  Consequences
   adopted: a value-equal duplicate key whose second serialization is
   non-minimal (`00` then `1800`) is multi-fault and the model reports
   the fault met first while tests accept either code; the B.7 item 9
   duplicate-unprotected-header construction is likewise multi-fault
   per the new B.7 note.  **Tests updated accordingly.**
3. *Unassigned CBOR simple values (classification consequence).*  The
   v0.8 layering leaves well-formed unassigned simple values outside
   both 6.1.1 and the 6.1.2 forbidden list (floats, `undefined`, tags),
   so they fall through to the schema layer.  **Code change:**
   reclassified from `nonDeterministicCbor` to `schemaViolation`
   (revising recorded interpretation 7).  The ill-formed two-byte form
   below 32 remains `invalidCbor`.
4. *Section 6.1.1 key-equivalence boundaries (codifies existing
   behavior).*  Different serializations of one value are one key;
   values of different generic data-model types (`0` versus `false`)
   are *not* equivalent keys even if a host language compares them
   equal.  The model already held both properties (bytewise duplicate
   detection plus the v0.6-review exact-type label checks); the
   `true`-versus-`1` decoded-representation collision remains
   `schemaViolation` (interpretation 18), now explicitly supported by
   6.1.1.  **Comments and tests only.**
5. *Section 6.1.1 byte-string opacity (codifies existing behavior).*
   Recursion stops at byte-string boundaries; byte-string contents are
   never reinterpreted as CBOR by the enclosing decode.  The model's
   decoder already treated byte strings as opaque, and the COSE payload
   is decoded as a separate item in Section 8.1 step 4.  **Comments and
   tests only.**
6. *Section 8.1 steps 2 and 4 (editorial for this model).*  The steps
   now name the Section 6.1 classifications and the recursive
   enforcement inside unknown extension values; behavior follows from
   changes 1-5.  **Comments only.**
7. *Appendix B.7 items 18 and the item 9/17 notes.*  New required
   mutation class: invalid RFC 3629 UTF-8 (overlong, surrogate, above
   U+10FFFF, incomplete), re-signed by the legitimate key, with
   fault-isolated vectors in B.10 producing `invalidCbor`.  **Tests
   added** (`test_mutations.py` item 18 class; B.10 reproduction).
8. *Appendix B.9 (new normative vectors).*  A second complete identity
   (Bob: seeds, descriptor, DID
   `did:flw:zQmdGJbJu6pBbiyZX9gJHBTFxnUCtBgRa7mZRcKKs1TcFEy`, timestamp
   `1785589201123`, complete Root record) for cross-DID state isolation
   and relay batches; migration vectors deferred to v0.8.1 by the
   specification.  **Fixture and tests added**; all Bob values
   reproduced byte-exactly from seeds and structured inputs.
9. *Appendix B.10 (new normative vectors).*  Five fault-isolated
   basic-validity records built from the B.4 body (`a6` → `a7` head,
   appended label-8 extension with key `https://example.com/ext`),
   re-signed with Alice's root seed: adjacent duplicate integer key,
   overlong U+002E, lone U+D800, U+110000, and an incomplete three-byte
   code point inside a complete two-byte text string.  All produce
   `invalidCbor`; reporting `invalidSignature` indicates the received
   bytes were altered.  **Fixture and tests added**; digests,
   Sig_structure lengths, and signatures reproduced byte-exactly.
10. *Relay-protocol changes (out of the model's scope).*  Sections 12.1,
    12.3, 12.6, 13.3, 14.1, 15.4, 16.16, 20.2, 20.3, 20.4, the Appendix
    A positional/`.cbor`-control notes, and the Appendix B.11 vectors
    define outer-wrapper validation and HTTP 400 versus per-item
    errors, duplicate-DID batch cardinality and positional isolation,
    `itemLimit` overflow rejection, synchronization cursor progress
    despite rejected candidates, and incremental-convergence liveness.
    The model deliberately contains no relay wire protocol (scope:
    Sections 3-8), so no code models these; recorded here for
    completeness of the delta.  The B.11 vectors are therefore not
    extracted into fixtures.
11. *Section 7.5 wording (editorial).*  "absolute-URI-keyed" becomes
    "Section 7.2 URI-keyed", harmonizing with Sections 5.6/7.2 as
    already implemented by the v0.7 pass (extension keys validated with
    `is_uri`).  **No change.**
12. *Section 1.1, 15.3 table wording, Section 22 freeze list, Appendix
    C reference 21 (RFC 3629), Section 20.1 additions.*  Status text,
    the frozen "basic-validity classification ... byte-string opacity
    boundary" items, and conformance-list entries corresponding to the
    changes above.  **Documentation/tests only.**

**Changes made.**

- Code: `followee_model/detcbor.py` (duplicate map keys and invalid
  UTF-8 reclassified `invalidCbor`; unassigned simple values
  reclassified `schemaViolation`; docstring rewritten around the
  Section 6.1 layers and multi-fault rule), `followee_model/verify.py`
  (step 2/4 comments), `followee_model/__init__.py` (docstring
  version).
- Fixtures: new `fixtures/specification/appendix_b_v08.json`,
  mechanically extracted by hand from Appendix B.9 and B.10 of the
  pinned `inputs/v0.8/Followee-Specification.md` in this repository
  (provenance block embedded in the file); the pre-v0.8
  `appendix_b.json` is unchanged and remains valid because B.2-B.8 are
  textually identical in v0.8.
- Tests: `tests/test_detcbor.py` (reclassified expectations; new
  nested-duplicate, RFC 3629 class, recursive-position, byte-string
  opacity, and multi-fault cases), `tests/test_mutations.py`
  (fault-isolated adjacent duplicate `invalidCbor`; out-of-order and
  unprotected-header duplicates as multi-fault either-code; new B.7
  item 18 class with valid-UTF-8 control), new
  `tests/test_v08_conformance.py` (B.9 Bob reproduction and
  verification, cross-DID identity-binding and selection isolation,
  B.10 reproduction with exact `invalidCbor` assertions).
- Documentation: this section; interpretation 6 marked resolved and 7
  revised; `tools/python-model/README.md` updated.

**Ambiguities found in the v0.8 delta.**

1. *Multi-fault classification is deliberately unspecified* (Section
   6.1.3), so it is recorded as adopted flexibility rather than an
   ambiguity: the model reports the first fault its single-pass decoder
   meets, and tests assert membership in the applicable error set.
2. *Unassigned CBOR simple values* are still not named by any layer of
   Section 6.1.  `schemaViolation` is this clean-room model's
   independently derived interpretation, following from the layered
   classification (such a value passes Sections 6.1.1 and 6.1.2 and is
   admitted by no schema).  An unassigned simple value can be a
   single-fault input, so Section 6.1.3's unspecified multi-fault
   precedence does not apply to it.  If another implementation later
   differs on a fault-isolated unassigned-simple-value case, that
   disagreement must open a specification or implementation review
   issue; it must not be treated as permitted multi-fault variation.
   (Corrected wording; see the post-maintenance review note below.)
3. *`invalidCbor` versus `nonDeterministicCbor` for indefinite
   lengths*: RFC 8949 treats indefinite-length items as well-formed,
   and Section 6.1.2 rule 1 requires definite lengths, so the model
   keeps `nonDeterministicCbor` for them; noted because rule 7's
   "profile-forbidden encoding" phrasing could invite `invalidCbor`
   readings elsewhere.

**External material consulted for the v0.8 pass.**  None fetched over
the network.  RFC 3629's invalid-UTF-8 classes (overlong, surrogates,
above U+10FFFF, incomplete sequences) are restated inside the v0.8
specification text itself; Python 3.10's strict `bytes.decode("utf-8")`
was verified in-session to reject all four classes, so the existing
standard-library decoder satisfies Section 6.1.1 (RFC 3629 added to the
standards table's scope via this note; URL
https://www.rfc-editor.org/rfc/rfc3629).  RFC 8949 Sections 5.3/5.6
basic-validity definitions were applied from working knowledge (already
listed in the standards table).  No new dependencies were added; the
model remains Python 3.10 standard-library only.

**Exclusion statement.**  No excluded or provisional Followee material
was inspected, searched for, received, or supplied during this pass: no
prose summary of the v0.7→v0.8 changes, affected-section list,
amendment rationale, or expected-change checklist; no `followee-rs`
source, tests, documentation, issues, CI output, diffs, or history; no
whitepaper; no `IMPLEMENTATION.md`, `SPEC-QUESTIONS.md`,
conformance-interface material, or `tools/spec_vector_check.py`; no
implementation-status or provisional fixtures; no Rust-derived expected
outputs; no baseline archives, promotion proposals, or mutation,
fuzzing, coverage, conformance, interoperability, or differential
reports; and no GitHub or web searches for Followee material.  The only
inputs were this repository at commit `5d00c79` (including its own Git
history) and the three approved files verified by SHA-256 against
`AUTHORING-CONSTRAINTS.md` before any change.

## Post-maintenance review note (2026-08-07)

An independent review of the v0.8 maintenance commit
`8a681abe854feea2a20e42b8f0980237fb27296a`, conducted using only the
pinned v0.8 specification and this repository's published clean-room
source, reported one documentation-only classification issue: ambiguity
2 above originally described the unassigned-simple-value classification
as a possible symbolic difference under Section 20.4's category for
differences permitted by unspecified multi-fault precedence.  That
category does not apply, because an unassigned simple value can be a
single-fault input; Section 6.1.3's unspecified-precedence rule covers
only inputs that independently violate more than one rule.  The
ambiguity text was reworded to state that `schemaViolation` is the
model's independently derived interpretation and that a future
fault-isolated disagreement with another implementation must open a
specification or implementation review issue rather than being recorded
as permitted multi-fault variation.

This correction changes wording only: no protocol code, test, fixture,
or the derived interpretation itself was modified.  The correction was
derived solely from the pinned v0.8 specification and the clean-room
source; no excluded, provisional, Rust-derived, or differential
material was inspected, searched for, or received in raising or
applying it, and no GitHub or web search was performed.

## Reproduction confidence

All 193 unit tests pass (155 at the v0.6 freeze, plus 5 post-freeze
regression tests, plus 13 v0.7 conformance and regression tests, plus
20 v0.8 conformance, mutation, and decoder-classification tests),
including byte-exact independent reproduction of
every Appendix B value from seeds and structured inputs — now including
the v0.8 B.9 Bob identity and all five B.10 fault-isolated
basic-validity vectors (bodies, digests, Sig_structure lengths,
signatures) — the three identity-binding permutations of B.7 item 1,
the B.7 mutation list with its normative error assignments including
the new item 18 class, and the B.8 descriptor-substitution attack
(signature valid, rejected `identityBindingMismatch` at step 9).
