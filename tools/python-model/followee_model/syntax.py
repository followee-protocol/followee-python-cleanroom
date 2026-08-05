"""Fixed-syntax validators for Contact Document fields (Section 7).

All checks are grammar-only: registry contents are never consulted
(Section 7.3).  Grammars implemented:

* absolute URI: RFC 3986 ``absolute-URI`` (scheme required; no fragment —
  see AUTHORING-RECORD.md for the recorded interpretation);
* mediaType: RFC 6838 ``restricted-name "/" restricted-name``;
* language: RFC 5646 ``Language-Tag`` well-formedness, case-insensitive,
  including the fixed grandfathered productions;
* rel token: RFC 8288 ``reg-rel-type``;
* service id: RFC 3986 ``unreserved`` characters, 1-256 of them.
"""

import re

# --- RFC 3986 absolute-URI -------------------------------------------------

_HEXDIG = "0-9A-Fa-f"
_PCT = f"%[{_HEXDIG}]{{2}}"
_UNRESERVED = r"[A-Za-z0-9._~-]"
_SUB_DELIMS = r"[!$&'()*+,;=]"
_PCHAR = f"(?:{_UNRESERVED}|{_PCT}|{_SUB_DELIMS}|[:@])"
_SCHEME = r"[A-Za-z][A-Za-z0-9+.-]*"
_USERINFO = f"(?:{_UNRESERVED}|{_PCT}|{_SUB_DELIMS}|:)*"
_DEC_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
_IPV4 = f"(?:{_DEC_OCTET}\\.){{3}}{_DEC_OCTET}"
_H16 = f"[{_HEXDIG}]{{1,4}}"
_LS32 = f"(?:{_H16}:{_H16}|{_IPV4})"
_IPV6 = "|".join(
    [
        f"(?:{_H16}:){{6}}{_LS32}",
        f"::(?:{_H16}:){{5}}{_LS32}",
        f"(?:{_H16})?::(?:{_H16}:){{4}}{_LS32}",
        f"(?:(?:{_H16}:)?{_H16})?::(?:{_H16}:){{3}}{_LS32}",
        f"(?:(?:{_H16}:){{0,2}}{_H16})?::(?:{_H16}:){{2}}{_LS32}",
        f"(?:(?:{_H16}:){{0,3}}{_H16})?::{_H16}:{_LS32}",
        f"(?:(?:{_H16}:){{0,4}}{_H16})?::{_LS32}",
        f"(?:(?:{_H16}:){{0,5}}{_H16})?::{_H16}",
        f"(?:(?:{_H16}:){{0,6}}{_H16})?::",
    ]
)
_IPVFUTURE = f"v[{_HEXDIG}]+\\.(?:{_UNRESERVED}|{_SUB_DELIMS}|:)+"
_IP_LITERAL = f"\\[(?:{_IPV6}|{_IPVFUTURE})\\]"
_REG_NAME = f"(?:{_UNRESERVED}|{_PCT}|{_SUB_DELIMS})*"
_HOST = f"(?:{_IP_LITERAL}|{_IPV4}|{_REG_NAME})"
_AUTHORITY = f"(?:{_USERINFO}@)?{_HOST}(?::[0-9]*)?"
_SEGMENT = f"{_PCHAR}*"
_SEGMENT_NZ = f"{_PCHAR}+"
_PATH_ABEMPTY = f"(?:/{_SEGMENT})*"
_PATH_ABSOLUTE = f"/(?:{_SEGMENT_NZ}(?:/{_SEGMENT})*)?"
_PATH_ROOTLESS = f"{_SEGMENT_NZ}(?:/{_SEGMENT})*"
_HIER_PART = f"(?://{_AUTHORITY}{_PATH_ABEMPTY}|{_PATH_ABSOLUTE}|{_PATH_ROOTLESS}|)"
_QUERY = f"(?:{_PCHAR}|[/?])*"
_ABSOLUTE_URI = re.compile(f"{_SCHEME}:{_HIER_PART}(?:\\?{_QUERY})?")


def is_absolute_uri(value) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and _ABSOLUTE_URI.fullmatch(value) is not None
    )


# --- RFC 6838 media type ---------------------------------------------------

_RESTRICTED_NAME = r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}"
_MEDIA_TYPE = re.compile(f"{_RESTRICTED_NAME}/{_RESTRICTED_NAME}")


def is_media_type(value) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and _MEDIA_TYPE.fullmatch(value) is not None
    )


# --- RFC 5646 Language-Tag well-formedness ---------------------------------

_EXTLANG = r"[a-z]{3}(?:-[a-z]{3}){0,2}"
_LANGUAGE = f"(?:[a-z]{{2,3}}(?:-{_EXTLANG})?|[a-z]{{4}}|[a-z]{{5,8}})"
_SCRIPT = r"[a-z]{4}"
_REGION = r"(?:[a-z]{2}|[0-9]{3})"
_VARIANT = r"(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3})"
_SINGLETON = r"[0-9a-wy-z]"
_EXTENSION = f"{_SINGLETON}(?:-[a-z0-9]{{2,8}})+"
_PRIVATEUSE = r"x(?:-[a-z0-9]{1,8})+"
_IRREGULAR = (
    "(?:en-gb-oed|i-ami|i-bnn|i-default|i-enochian|i-hak|i-klingon|i-lux"
    "|i-mingo|i-navajo|i-pwn|i-tao|i-tay|i-tsu|sgn-be-fr|sgn-be-nl|sgn-ch-de)"
)
_REGULAR = (
    "(?:art-lojban|cel-gaulish|no-bok|no-nyn|zh-guoyu|zh-hakka|zh-min"
    "|zh-min-nan|zh-xiang)"
)
_LANGTAG = (
    f"{_LANGUAGE}(?:-{_SCRIPT})?(?:-{_REGION})?"
    f"(?:-{_VARIANT})*(?:-{_EXTENSION})*(?:-{_PRIVATEUSE})?"
)
_LANGUAGE_TAG = re.compile(
    f"(?:{_LANGTAG}|{_PRIVATEUSE}|{_IRREGULAR}|{_REGULAR})", re.IGNORECASE
)


def is_language_tag(value) -> bool:
    return (
        isinstance(value, str)
        and value.isascii()
        and _LANGUAGE_TAG.fullmatch(value) is not None
    )


# --- RFC 8288 reg-rel-type -------------------------------------------------

_REG_REL_TYPE = re.compile(r"[a-z][a-z0-9.-]*")


def is_rel_token(value) -> bool:
    return isinstance(value, str) and _REG_REL_TYPE.fullmatch(value) is not None


# --- Service identifier ----------------------------------------------------

_SERVICE_ID = re.compile(r"[A-Za-z0-9._~-]{1,256}")


def is_service_id(value) -> bool:
    return isinstance(value, str) and _SERVICE_ID.fullmatch(value) is not None
