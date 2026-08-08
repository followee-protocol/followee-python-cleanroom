"""Identity Record body and Contact Document schema validation
(Sections 5, 7, 15.1).

Deterministic-encoding properties (ordering, minimality, duplicate keys,
forbidden types) and the aggregate depth/member limits are enforced by the
strict decoder in :mod:`followee_model.detcbor`; this module validates the
decoded structure against the v1 schema and the remaining limits.
"""

from . import detcbor, did as did_module, syntax
from .errors import ErrorCode, FolloweeError

UINT64_MAX = 2**64 - 1

MAX_RECORD_BODY_DEPTH = 8
MAX_RECORD_BODY_MEMBERS = 256
MAX_CONTACT_BYTES = 12 * 1024
MAX_DISPLAY_NAME_BYTES = 256
MAX_SUMMARY_BYTES = 2048
MAX_URI_BYTES = 2048
MAX_ALSO_KNOWN_AS = 32
MAX_SERVICES = 64
MAX_SERVICE_ID_BYTES = 256
MAX_SERVICE_LABEL_BYTES = 256
MAX_MEDIA_TYPE_BYTES = 256
MAX_LANGUAGE_BYTES = 64
MAX_REL_BYTES = 256
MAX_EXTENSION_KEY_BYTES = 256

SERVICE_TYPE_TOKENS = frozenset(
    {
        "Website",
        "Feed",
        "Profile",
        "ActivityPub",
        "Messaging",
        "Repository",
        "Payment",
        "Other",
    }
)

AUTHORITY_ROOT = 0
AUTHORITY_ROOT_REVOKED = 1

_REQUIRED_BODY_LABELS = frozenset({0, 1, 2, 3, 4, 7})
_KNOWN_BODY_LABELS = frozenset(range(9))


def _schema(message: str) -> FolloweeError:
    return FolloweeError(ErrorCode.SCHEMA_VIOLATION, message)


def _require_uint64(value, name: str) -> int:
    if type(value) is not int or value < 0 or value > UINT64_MAX:
        raise _schema(f"{name} must be an unsigned 64-bit integer")
    return value


def _utf8_length(value: str) -> int:
    return len(value.encode("utf-8"))


def validate_record_body(body) -> None:
    """Top-level record-body structure (Section 5.1): known integer labels
    only, required labels present, correct value types.

    The authority-conditional presence of label 5 is enforced separately
    (Section 8.1 step 10), as are descriptor content, revealed-key content,
    Contact Document content, and the validUntil relation.
    """
    if not isinstance(body, dict):
        raise _schema("record body must be a map")
    for label in body:
        if type(label) is not int:
            raise _schema("record-body labels must be unsigned integers")
        if label not in _KNOWN_BODY_LABELS:
            raise _schema(f"unknown record-body label {label}")
    missing = _REQUIRED_BODY_LABELS - set(body.keys())
    if missing:
        raise _schema(f"missing required record-body labels {sorted(missing)}")

    protocol_version = body[0]
    if type(protocol_version) is not int or protocol_version != 1:
        raise _schema("protocolVersion must equal 1")
    if not isinstance(body[1], str):
        raise _schema("id must be a text string")
    _require_uint64(body[2], "timestamp_ms")
    authority = body[3]
    if type(authority) is not int or authority not in (
        AUTHORITY_ROOT,
        AUTHORITY_ROOT_REVOKED,
    ):
        raise _schema("authority must be 0 or 1")
    if not isinstance(body[4], dict):
        raise _schema("authorityDescriptor must be a map")
    if 5 in body and not isinstance(body[5], dict):
        raise _schema("revocationKey must be a public-key map")
    if 6 in body:
        _require_uint64(body[6], "validUntil_ms")
    if not isinstance(body[7], dict):
        raise _schema("contact must be a map")
    if 8 in body and not isinstance(body[8], dict):
        raise _schema("extensions must be a map")


def validate_extension_value(value, context: str) -> None:
    """Extension values are limited to the CBOR types in Appendix A
    (Section 5.6): uint, nint, bstr, tstr, bool, nil, arrays, and objects
    whose inner keys are uint, nint, or tstr."""
    if value is None or value is True or value is False:
        return
    if type(value) is int:
        # The strict decoder already bounds integers to the basic CBOR
        # integer range; re-check for structurally built inputs.
        if value > UINT64_MAX or value < -(2**64):
            raise _schema(f"{context}: extension integer out of range")
        return
    if isinstance(value, (bytes, str)):
        return
    if isinstance(value, list):
        for item in value:
            validate_extension_value(item, context)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not int and not isinstance(key, str):
                raise _schema(f"{context}: extension object key must be int or tstr")
            validate_extension_value(item, context)
        return
    if isinstance(value, detcbor.SimpleValue):
        # Deterministic but schema-disallowed simple value (Section 6.1.2
        # v0.8.1 paragraph, Appendix B.12): passes the deterministic-CBOR
        # layer and is rejected here by the Appendix A extension-value
        # schema.
        raise _schema(
            f"{context}: CBOR simple value {value.value} is not admitted "
            "by the extension-value schema"
        )
    raise _schema(f"{context}: forbidden extension value type")


def validate_extension_map(extensions, context: str) -> None:
    """Extension map keyed by URI strings satisfying Section 7.2
    (Sections 5.6 and 7.5)."""
    if not isinstance(extensions, dict):
        raise _schema(f"{context}: extension map must be a map")
    for key, value in extensions.items():
        if not isinstance(key, str):
            raise _schema(f"{context}: extension keys must be text strings")
        if _utf8_length(key) > MAX_EXTENSION_KEY_BYTES:
            raise _schema(f"{context}: extension key exceeds 256 bytes")
        if not syntax.is_uri(key):
            raise _schema(f"{context}: extension key must be an RFC 3986 URI")
        validate_extension_value(value, context)


def _validate_uri_field(value, name: str) -> None:
    if not isinstance(value, str):
        raise _schema(f"{name} must be a text string")
    if _utf8_length(value) > MAX_URI_BYTES:
        raise _schema(f"{name} exceeds {MAX_URI_BYTES} bytes")
    if not syntax.is_uri(value):
        raise _schema(f"{name} must be an RFC 3986 URI")


def validate_service_entry(entry, index: int, seen_ids: set) -> None:
    name = f"service[{index}]"
    if not isinstance(entry, dict):
        raise _schema(f"{name} must be a map")
    for label in entry:
        if type(label) is not int or label not in range(7):
            raise _schema(f"{name}: unknown service label {label!r}")
    for label in (0, 1, 2):
        if label not in entry:
            raise _schema(f"{name}: missing required service label {label}")

    service_id = entry[0]
    if not syntax.is_service_id(service_id):
        raise _schema(f"{name}: id must be 1-256 ASCII unreserved characters")
    if service_id in seen_ids:
        raise _schema(f"{name}: duplicate service id {service_id!r}")
    seen_ids.add(service_id)

    service_type = entry[1]
    if not isinstance(service_type, str):
        raise _schema(f"{name}: type must be a text string")
    if service_type not in SERVICE_TYPE_TOKENS:
        _validate_uri_field(service_type, f"{name}.type")

    _validate_uri_field(entry[2], f"{name}.endpoint")

    if 3 in entry:
        media_type = entry[3]
        if not isinstance(media_type, str):
            raise _schema(f"{name}: mediaType must be a text string")
        if _utf8_length(media_type) > MAX_MEDIA_TYPE_BYTES:
            raise _schema(f"{name}: mediaType exceeds 256 bytes")
        if not syntax.is_media_type(media_type):
            raise _schema(f"{name}: mediaType violates RFC 6838 syntax")
    if 4 in entry:
        label_value = entry[4]
        if not isinstance(label_value, str):
            raise _schema(f"{name}: label must be a text string")
        if _utf8_length(label_value) > MAX_SERVICE_LABEL_BYTES:
            raise _schema(f"{name}: label exceeds 256 bytes")
    if 5 in entry:
        language = entry[5]
        if not isinstance(language, str):
            raise _schema(f"{name}: language must be a text string")
        if _utf8_length(language) > MAX_LANGUAGE_BYTES:
            raise _schema(f"{name}: language exceeds 64 bytes")
        if not syntax.is_language_tag(language):
            raise _schema(f"{name}: language violates RFC 5646 syntax")
    if 6 in entry:
        rel = entry[6]
        if not isinstance(rel, str):
            raise _schema(f"{name}: rel must be a text string")
        if _utf8_length(rel) > MAX_REL_BYTES:
            raise _schema(f"{name}: rel exceeds 256 bytes")
        if not syntax.is_rel_token(rel) and not syntax.is_uri(rel):
            raise _schema(f"{name}: rel must be a reg-rel-type or RFC 3986 URI")


def validate_migration(migration, own_did: str) -> None:
    if not isinstance(migration, dict):
        raise _schema("migration must be a map")
    for label in migration:
        if type(label) is not int or label not in (0, 1):
            raise _schema(f"migration: unknown label {label!r}")
    if not migration:
        raise _schema("migration map must contain at least one field")
    for label, name in ((0, "predecessor"), (1, "successor")):
        if label not in migration:
            continue
        value = migration[label]
        if not isinstance(value, str):
            raise _schema(f"migration.{name} must be a text string")
        try:
            did_module.parse_did(value)
        except FolloweeError:
            raise _schema(
                f"migration.{name} must be a canonical v1 Followee DID"
            ) from None
        if value == own_did:
            raise _schema(f"migration.{name} must differ from the record's DID")


def validate_contact(contact, own_did: str) -> None:
    """Full Contact Document validation (Section 7 and its limits)."""
    if not isinstance(contact, dict):
        raise _schema("contact must be a map")
    for label in contact:
        if type(label) is not int or label not in range(7):
            raise _schema(f"contact: unknown label {label!r}")

    if len(detcbor.encode(contact)) > MAX_CONTACT_BYTES:
        raise _schema(f"contact document exceeds {MAX_CONTACT_BYTES} bytes")

    if 0 in contact:
        value = contact[0]
        if not isinstance(value, str):
            raise _schema("displayName must be a text string")
        if _utf8_length(value) > MAX_DISPLAY_NAME_BYTES:
            raise _schema("displayName exceeds 256 bytes")
    if 1 in contact:
        value = contact[1]
        if not isinstance(value, str):
            raise _schema("summary must be a text string")
        if _utf8_length(value) > MAX_SUMMARY_BYTES:
            raise _schema("summary exceeds 2048 bytes")
    if 2 in contact:
        _validate_uri_field(contact[2], "avatar")
    if 3 in contact:
        entries = contact[3]
        if not isinstance(entries, list):
            raise _schema("alsoKnownAs must be an array")
        if len(entries) > MAX_ALSO_KNOWN_AS:
            raise _schema("alsoKnownAs exceeds 32 entries")
        for index, entry in enumerate(entries):
            _validate_uri_field(entry, f"alsoKnownAs[{index}]")
    if 4 in contact:
        services = contact[4]
        if not isinstance(services, list):
            raise _schema("services must be an array")
        if len(services) > MAX_SERVICES:
            raise _schema("services exceeds 64 entries")
        seen_ids: set = set()
        for index, entry in enumerate(services):
            validate_service_entry(entry, index, seen_ids)
    if 5 in contact:
        validate_migration(contact[5], own_did)
    if 6 in contact:
        validate_extension_map(contact[6], "contact.extensions")
