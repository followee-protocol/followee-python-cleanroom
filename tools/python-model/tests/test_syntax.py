import unittest

from followee_model import syntax


class UriTests(unittest.TestCase):
    def test_valid(self):
        for uri in (
            "https://alice.example/feed.xml",
            "https://example.com/",
            "https://example.com",
            "acct:alice@example.com",
            "did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm",
            "mailto:a@b.example",
            "urn:example:animal:ferret:nose",
            "https://user:pw@example.com:8443/a/b?x=1&y=%20z",
            "https://[2001:db8::1]/path",
            "https://[v7.ab:12]/x",  # IPvFuture, lowercase v
            "https://[V7.ab]/x",  # IPvFuture, uppercase V (ABNF literals)
            "https://192.0.2.7:80/x",
            "scheme+ext.x-1:",
            "https://example.com/a%2Fb",
            # v0.7 Section 7.2: the URI production permits fragments.
            "https://example.com/profile#about",
            "did:web:example.com#key-1",
            "https://example.com/a?x=1#y/z?w",
            "https://example.com/#",  # empty fragment is valid
            "https://example.com/#%20x",
        ):
            self.assertTrue(syntax.is_uri(uri), uri)

    def test_invalid(self):
        for uri in (
            "",
            "/relative/path",  # absolute-path reference
            "//example.com/x",  # network-path reference
            "example.com/x",  # relative-path reference
            "?view=full",  # query-only reference
            "#about",  # fragment-only reference
            "1https://example.com",
            "https://exa mple.com/",
            "https://example.com/%2",
            "https://example.com/%zz",
            "https://example.com/\u00e9",
            "https://example.com/a#b#c",  # '#' not permitted inside fragment
            "https://example.com/#frag%2",  # bad pct-encoding in fragment
            "http s://example.com",
            ":nopath",
        ):
            self.assertFalse(syntax.is_uri(uri), uri)


class MediaTypeTests(unittest.TestCase):
    def test_valid(self):
        for value in (
            "application/atom+xml",
            "text/plain",
            "application/vnd.example.thing+json",
            "Text/Plain",
            "a/b",
            "x" * 127 + "/" + "y" * 127,
        ):
            self.assertTrue(syntax.is_media_type(value), value)

    def test_invalid(self):
        for value in (
            "",
            "text",
            "text/",
            "/plain",
            "text/plain;charset=utf-8",
            "text/pla in",
            "te?xt/plain",
            ".text/plain",
            "+a/b",
            "x" * 128 + "/y",
            "a/b/c",
        ):
            self.assertFalse(syntax.is_media_type(value), value)


class LanguageTagTests(unittest.TestCase):
    def test_valid(self):
        for value in (
            "en",
            "en-US",
            "en-us",
            "EN-GB",
            "zh-Hant-TW",
            "sl-rozaj-biske",
            "de-CH-1901",
            "es-419",
            "az-Latn",
            "en-a-bbb-x-a-ccc",
            "x-private-tag",
            "i-klingon",
            "en-GB-oed",
            "zh-min-nan",
            "sgn-BE-FR",
            "yue-HK",
        ):
            self.assertTrue(syntax.is_language_tag(value), value)

    def test_invalid(self):
        for value in (
            "",
            "a",
            "a-DE",
            "en--US",
            "en-",
            "-en",
            "en-US-",
            "toolonglanguage",
            "en-x",
            "en-a",
            "x",
            "en US",
            "de-419-DE",  # region cannot appear twice
            "123",
        ):
            self.assertFalse(syntax.is_language_tag(value), value)


class RelTokenTests(unittest.TestCase):
    def test_valid_tokens(self):
        for value in ("me", "alternate", "a", "describedby", "x.y-z2"):
            self.assertTrue(syntax.is_rel_token(value), value)

    def test_invalid_tokens(self):
        for value in ("", "ME", "Alternate", "9me", "-me", ".x", "a_b", "a b"):
            self.assertFalse(syntax.is_rel_token(value), value)


class ServiceIdTests(unittest.TestCase):
    def test_valid(self):
        for value in ("feed", "a", "A-b_c.d~e", "x" * 256):
            self.assertTrue(syntax.is_service_id(value), value)

    def test_invalid(self):
        for value in ("", "x" * 257, "a b", "a/b", "a%20b", "f\u00e9ed"):
            self.assertFalse(syntax.is_service_id(value), value)


if __name__ == "__main__":
    unittest.main()
