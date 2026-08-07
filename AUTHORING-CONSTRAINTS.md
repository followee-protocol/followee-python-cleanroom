# Followee Python Model: Clean-room Authoring Constraints

This repository is an isolated workspace for an independent Python model of
the Followee protocol core. Its purpose is to detect interpretations or
mistakes shared by the Rust implementation and its tests.

The model was independently authored against specification v0.6, corrected
under post-freeze review, and maintained to specification v0.7 without
receiving excluded Followee material. This document now governs the bounded
maintenance pass from v0.7 to v0.8. That pass preserves independence from the
Rust implementation, but it is not represented as fresh authorship from a
blank workspace.

## Preserved v0.6 baseline

The following revisions remain the audit trail for the original clean-room
work:

| Artefact | Revision |
| --- | --- |
| Approved-input commit | `70b393fa15d7fa550b1864ff28a86a8a20726561` |
| Original independently authored freeze | `7ca1f623453065deefd1e6cfdf15e135d523dd7e` (`cleanroom-v0.6-freeze`) |
| Post-freeze reviewed correction | `70e4a6caa8720f1dfbb3b183a5d305fca0cf3e57` (`cleanroom-v0.6-review1`) |

The original approved inputs were:

| File | Source revision | SHA-256 | Status |
| --- | --- | --- | --- |
| `Followee-Specification.md` | `followee-protocol/followee` commit `44c68660f0c0a1e3504c0f9794b8c51058da6f18` | `09e5f70c0cc6a3e0d2cf99471437e0e7099e3413046791fcce0931147671ce5f` | Normative specification v0.6 |
| `fixtures/specification/appendix_b.json` | `followee-protocol/followee-rs` commit `32c9f336c921797753d728bd39549a0870dee837` | `f188316ffd7ad07fe94a842027f1ea7596e42a2f00b0691c1096fa2bfaddb717` | Specification-status Appendix B fixture |

The tags and commits above MUST NOT be moved, rewritten, squashed, or deleted.

## Approved v0.7 maintenance inputs (historical)

Only the following Followee-specific material may be used during the v0.7
maintenance pass:

| Input | Revision or digest | Status |
| --- | --- | --- |
| This clean-room repository's own source, tests, records, and history | through commit `70e4a6caa8720f1dfbb3b183a5d305fca0cf3e57` | Reviewed independent v0.6 model |
| `Followee-Specification.md` | `followee-protocol/followee` commit `abc9a55d90f1026e6509207abda73e5dc6d14241`; SHA-256 `2b264823ba68d9a7d69ce68de5c1408ac8a3d54ff6d726ab89ee2baa2707c81f` | Normative specification v0.7 |
| `fixtures/specification/appendix_b.json` already present in this repository | SHA-256 `f188316ffd7ad07fe94a842027f1ea7596e42a2f00b0691c1096fa2bfaddb717` | Unchanged specification-status Appendix B fixture |

The normative v0.7 specification governs. The JSON fixture is a mechanically
extracted representation of values published in Appendix B and does not
supersede the specification. Its presence does not authorise access to its
source repository.

## Excluded material during v0.7 maintenance (historical)

Until the reviewed v0.7 maintenance revision is committed and frozen, the
maintenance session MUST NOT inspect, search for, or receive:

- the `followee-rs` source, tests, documentation, issues, pull requests, CI
  output, releases, or Git history;
- the Followee whitepaper;
- `IMPLEMENTATION.md`;
- `SPEC-QUESTIONS.md`;
- `tools/spec_vector_check.py`;
- implementation-status or provisional fixtures;
- Rust-derived expected outputs;
- mutation, fuzzing, coverage, conformance, interoperability, or differential
  reports from another implementation;
- previous reviews or conversations that disclose another implementation's
  behaviour; or
- any other Followee repository or unpublished Followee material not listed
  under approved inputs.

The maintenance session MUST NOT search GitHub or the public web for additional
Followee material. It may use this repository's own Git history because that
history is itself an approved input.

## Permitted external material

The maintainer may consult normative external standards cited by the
specification and ordinary documentation for independently selected Python
dependencies. Every such source consulted MUST be recorded in
`AUTHORING-RECORD.md`, including its URL or package version.

## v0.7 maintenance procedure (historical)

The maintenance pass is performed in the existing clean-room conversation or
another context containing only the approved inputs above. It shares no
protocol code, generated parser, fixture generator, algorithmic helper, or
expected output with another Followee implementation.

Before modifying the model, the maintainer MUST:

1. verify that commit `70e4a6caa8720f1dfbb3b183a5d305fca0cf3e57`
   descends directly from the preserved v0.6 freeze as recorded above;
2. verify the SHA-256 digests of the v0.7 specification and unchanged Appendix
   B fixture against this document; and
3. read the complete pinned v0.7 specification and determine the semantic
   delta from the repository's recorded v0.6 input without consulting another
   implementation.

Questions or ambiguities are recorded rather than resolved by consulting an
existing implementation. Every interpretation or model change introduced by
the v0.7 pass MUST be recorded in `AUTHORING-RECORD.md`, including whether the
change affects code, tests, or documentation only.

The maintainer then runs the complete clean-room test suite and commits the
updated model, tests, constraints, specification input, and authoring record.
That commit is reviewed and frozen under a new v0.7 maintenance tag before any
excluded or provisional material is revealed. The record MUST identify the
v0.6 base, the v0.7 specification commit, and the resulting model commit.

After that freeze, differential testing may supply provisional input bytes to
the unchanged model. Rust-derived expected results must never be supplied as
authoring inputs. Agreement or disagreement is recorded by the differential
harness; it is not resolved by silently changing the frozen model.

## Preserved v0.7 maintenance freeze

The reviewed v0.7 model is frozen at:

| Artefact | Revision |
| --- | --- |
| v0.7 maintenance input | `6b944b952d1daec6840deae7e07f304f5349637d` |
| Reviewed v0.7 maintenance freeze | `a39138dae8072c7b89dc922bcfe6f5717312c6e6` (`cleanroom-v0.7-maintenance-freeze`) |

The freeze above and every earlier tag and commit named by this document MUST
NOT be moved, rewritten, squashed, or deleted.

## Approved v0.8 maintenance inputs

Only the following Followee-specific material may be used during the v0.8
maintenance pass:

| Input | Revision or digest | Status |
| --- | --- | --- |
| This clean-room repository's own source, tests, records, and Git history | through commit `a39138dae8072c7b89dc922bcfe6f5717312c6e6` | Reviewed independent model maintained through v0.7 |
| `Followee-Specification.md` | `followee-protocol/followee` commit `abc9a55d90f1026e6509207abda73e5dc6d14241`; SHA-256 `2b264823ba68d9a7d69ce68de5c1408ac8a3d54ff6d726ab89ee2baa2707c81f` | Normative specification v0.7 |
| `inputs/v0.8/Followee-Specification.md` | `followee-protocol/followee` commit `610f9a1e78d860e8bd685ef1435a53a16f1221ec`; SHA-256 `474f0b3880e838a5232890c3e2edc183c341fd25e28d7db0066ad109aa43113b` | Normative specification v0.8 |
| `fixtures/specification/appendix_b.json` already present in this repository | SHA-256 `f188316ffd7ad07fe94a842027f1ea7596e42a2f00b0691c1096fa2bfaddb717` | Specification-status values published before v0.8; useful only where the v0.8 specification leaves those values unchanged |

The normative v0.8 specification governs. The existing JSON fixture is not a
complete representation of v0.8 and does not supersede either specification.
Its presence does not authorise access to its source repository. New
specification-status inputs may be derived directly from the pinned v0.8
document within this repository, with their derivation recorded.

## Excluded material during v0.8 maintenance

Until the reviewed v0.8 maintenance revision is committed and frozen, the
maintenance session MUST NOT inspect, search for, or receive:

- a prose summary of the semantic changes between v0.7 and v0.8;
- a list of sections affected by the amendment or a checklist of expected
  implementation changes;
- the amendment rationale or protocol-review discussion that led to it;
- the Followee whitepaper;
- `IMPLEMENTATION.md` or any other implementation brief;
- the `followee-rs` source, tests, documentation, issues, pull requests, CI
  output, releases, diffs, or Git history;
- `SPEC-QUESTIONS.md`, conformance-interface material, or harness adapter
  contracts not contained in the normative specification;
- `tools/spec_vector_check.py` or another implementation's fixture-producing
  code;
- implementation-status or provisional fixtures;
- Rust-derived expected outputs;
- baseline archives, promotion proposals, or mutation, fuzzing, coverage,
  conformance, interoperability, or differential reports;
- previous reviews, prompts, messages, or conversations that disclose the
  intended interpretation of v0.8 or another implementation's behaviour; or
- any other Followee repository or unpublished Followee material not listed
  under approved inputs.

The maintenance session MUST NOT search GitHub or the public web for
additional Followee material. It may use this repository's own Git history
because that history is itself an approved input.

## v0.8 maintenance procedure

The maintenance pass is performed in a fresh conversation or another context
containing only the approved inputs above. It shares no protocol code,
generated parser, fixture generator, algorithmic helper, expected output, or
semantic change summary with another Followee implementation.

Before modifying the model, the maintainer MUST:

1. verify that the input-preparation commit is based directly on
   `a39138dae8072c7b89dc922bcfe6f5717312c6e6` and that the preserved freeze tag
   still peels to that commit;
2. verify the SHA-256 digests of both specification files and the existing
   Appendix B fixture against this document;
3. read both pinned specifications completely; and
4. derive and record the semantic delta independently, without receiving a
   summary, affected-section list, rationale, or expected-change checklist.

Questions or ambiguities are recorded rather than resolved by consulting an
existing implementation. Every interpretation or model change introduced by
the v0.8 pass MUST be recorded in `AUTHORING-RECORD.md`, including whether the
change affects code, tests, fixtures, or documentation only. The independently
derived change account is an output demonstrating comprehension of the two
specifications; it must not be copied from an input supplied to the session.

The maintainer then runs the complete clean-room test suite and commits the
updated model, tests, constraints, specification inputs, and authoring record.
That commit is reviewed and frozen under a new immutable v0.8 maintenance tag
before any excluded, provisional, Rust-derived, or differential material is
revealed. The record MUST identify the v0.7 base, both specification commits
and digests, the input-preparation commit, and the resulting model commit.

After that freeze, the differential harness may supply provisional input bytes
to the unchanged model. Expected results remain comparator-side and MUST NOT
be supplied to the adapter or model. Agreement or disagreement is recorded by
the harness; it is not resolved by silently changing the frozen model.
