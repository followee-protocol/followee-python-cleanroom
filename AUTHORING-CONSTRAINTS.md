# Followee Python Model: Clean-room Authoring Constraints

This repository is an isolated authoring workspace for an independent Python
model of the Followee protocol core. Its purpose is to detect interpretations
or mistakes shared by the Rust implementation and its tests.

## Approved Followee-specific inputs

Only the following Followee-specific material may be used during authoring:

| File | Source revision | SHA-256 | Status |
| --- | --- | --- | --- |
| `Followee-Specification.md` | `followee-protocol/followee` commit `44c68660f0c0a1e3504c0f9794b8c51058da6f18` | `09e5f70c0cc6a3e0d2cf99471437e0e7099e3413046791fcce0931147671ce5f` | Normative specification v0.6 |
| `fixtures/specification/appendix_b.json` | `followee-protocol/followee-rs` commit `32c9f336c921797753d728bd39549a0870dee837` | `f188316ffd7ad07fe94a842027f1ea7596e42a2f00b0691c1096fa2bfaddb717` | Specification-status fixture |

The normative specification governs. The JSON fixture is a mechanically
extracted representation of values published in Appendix B and does not
supersede the specification.

## Excluded material

The authoring session MUST NOT inspect, search for, or receive:

- the `followee-rs` source or Git history;
- Rust tests or generated documentation;
- the Followee whitepaper;
- `IMPLEMENTATION.md`;
- `SPEC-QUESTIONS.md`;
- `tools/spec_vector_check.py`;
- implementation-status or provisional fixtures;
- Rust-derived expected outputs;
- mutation, fuzzing, coverage, or differential-test reports;
- previous implementation reviews or conversations; or
- any other Followee repository or unpublished Followee material.

The authoring session MUST NOT search GitHub or the public web for additional
Followee material.

## Permitted external material

The author may consult normative external standards cited by the specification
and ordinary documentation for independently selected Python dependencies.
Every such source consulted MUST be recorded in `AUTHORING-RECORD.md`, including
its URL or package version.

## Authoring procedure

The model is authored in a fresh conversation rooted only in this repository.
It shares no protocol code, generated parser, fixture generator, or algorithmic
helper with another Followee implementation.

Questions or ambiguities are recorded rather than resolved by consulting an
existing implementation.

The completed model, tests, dependency lock information, and
`AUTHORING-RECORD.md` are committed and reviewed before any excluded or
provisional material is revealed. That commit becomes the clean-room freeze
revision.

After the freeze, differential testing may supply provisional input bytes to
the unchanged model. Rust-derived expected results must never be supplied as
authoring inputs.