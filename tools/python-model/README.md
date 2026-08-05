# Followee Python model (clean room)

An independent, deliberately direct Python model of the Followee protocol
core, authored solely from `Followee-Specification.md` (v0.6) and the
specification-status fixture `fixtures/specification/appendix_b.json`
under the constraints in `AUTHORING-CONSTRAINTS.md`.  Its purpose is
differential comparison against other implementations, so it favors
clarity and exact specification wording over performance.

## Scope

Sections 3-8 of the specification:

| Module | Covers |
| --- | --- |
| `followee_model/errors.py` | Symbolic wire error codes (Section 15.3) |
| `followee_model/detcbor.py` | Deterministic CBOR encode and strict decode (Section 6.1); exact received bytes are the bytes verified |
| `followee_model/base58.py` | Base58btc without padding |
| `followee_model/did.py` | DID syntax, multihash profile, `invalidDid` vs `unsupportedHash` (Sections 3.1, 4.3) |
| `followee_model/ed25519.py` | Pure RFC 8032 Ed25519 plus Followee-strict verification (Section 3.3) |
| `followee_model/descriptor.py` | Authority Descriptor, revocation commitment, descriptor digest, DID derivation (Section 4) |
| `followee_model/syntax.py` | Fixed grammars: absolute URI, mediaType, language, rel, service id (Section 7) |
| `followee_model/record.py` | Record body and Contact Document schemas and limits (Sections 5, 7, 15.1) |
| `followee_model/cose.py` | COSE Sign1 profile and `Sig_structure` (Section 6.2) |
| `followee_model/verify.py` | Full-record verification algorithm in step order (Section 8.1) |
| `followee_model/selection.py` | Deterministic candidate selection with sticky root revocation (Sections 8.2-8.4) |
| `followee_model/signing.py` | Record construction, signing, signer timestamps (Sections 4.4, 5.3) |

Out of scope by design: HTTP, relay state, persistence, CLI, and
differential testing.

There are no third-party dependencies; only the Python 3.10 standard
library is used.

## Tests

From this directory:

```sh
python3 -m unittest discover -s tests -t .
```

`tests/test_appendix_b.py` reproduces every derived value in Appendix B
(public keys, commitment, descriptor, DID, body bytes, Sig_structure,
digests, signatures, envelopes, and the B.8 substitution attack) from
structured inputs and compares them against the fixture; nothing from the
fixture is embedded in the model itself.  `tests/test_mutations.py`
exercises the required negative mutations of Appendix B.7 with their
normative error classifications.

Interpretation decisions and ambiguities encountered during authoring are
recorded in `../../AUTHORING-RECORD.md`.
