"""The list codec of libmavis (av_add_quoted, av_list_next, av_list_check), called in the installed libmavis.so.

TACMEMBER, MEMBEROF, SSHKEY, SSHKEYHASH and SSHKEYID use it; see mavis.h
for the grammar. The daemon and the groups module decode with it, the C
back-ends encode with it, and the Perl and Python back-ends have the
same encoder rule.
"""

import ctypes
import os
import unittest

from tactest import prefix
from tactest.daemon import sanitizers

LIBMAVIS = os.path.join(prefix(), "lib", "libmavis.so")
AV_A_TACMEMBER = 47

# input, the values; an input with a None value list is malformed
LISTS = (
    ("", []),
    ("  ", []),
    ("ops", ["ops"]),
    ("ops,admins", ["ops", "admins"]),
    (" ops , admins ", ["ops", "admins"]),
    ('"a",b,c', ["a", "b", "c"]),
    ('"a" , "b"', ["a", "b"]),
    ('"a,b"', ["a,b"]),
    ('""', [""]),
    ('" x "', [" x "]),
    ("'ops'", ["ops"]),
    (r"'a\'b'", ["a'b"]),
    ("'a\"b'", ['a"b']),
    ('a"b', ['a"b']),
    (r'"a\"b"', ['a"b']),
    (r'"a\\b"', [r"a\\b"]),
    (r'"cn=a\,b,dc=x"', [r"cn=a\,b,dc=x"]),
    (r'"cn=a\\,b,dc=x"', [r"cn=a\\,b,dc=x"]),
    ("a\\", ["a\\"]),
    ("a,,b", None),
    ("a,", None),
    ("a, ", None),
    (",a", None),
    ('"a",', None),
    ('"a" "b"', None),
    ('"a"b', None),
    ('"a', None),
    ('"', None),
    ("'", None),
    (r'"a\"', None),
    (r'"a\\"', None),
    ('"a\rb"', None),
    ('"a\nb"', None),
    ("a\nb", None),
    ("a\r", None),
    ('"a"\n"b"', None),
)

# values for a round trip through the encoder and the decoder
VALUES = (",", '"', "${X}", r"cn=a\,b", r"cn=a\\,b", "", " x ", "a,b", '\\"', "a\\b", "'", "\\'x")

# values the encoder refuses: the list cannot carry them
REFUSED = ("a\nb", "a\rb", "\n", "a\\", "\\")


@unittest.skipUnless(os.path.exists(LIBMAVIS), "no installed libmavis.so")
@unittest.skipIf(os.path.exists(LIBMAVIS) and sanitizers(),
                 "a sanitizer build of libmavis.so needs the sanitizer runtime of the daemon; the daemon tests use the codec")
class ListCodec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        lib = cls.lib = ctypes.CDLL(LIBMAVIS)
        lib.av_list_next.argtypes = (ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p),
                                     ctypes.POINTER(ctypes.c_int))
        lib.av_list_check.argtypes = (ctypes.c_char_p, ctypes.c_int)
        lib.av_new.restype = ctypes.c_void_p
        lib.av_new.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        lib.av_add_quoted.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t)
        lib.av_get.restype = ctypes.c_char_p
        lib.av_get.argtypes = (ctypes.c_void_p, ctypes.c_int)
        lib.av_free.argtypes = (ctypes.c_void_p,)
        lib.av_set.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p)

    def decode(self, text):
        """The values, or None for a malformed list."""
        buf = ctypes.create_string_buffer(text.encode())
        cursor = ctypes.cast(buf, ctypes.c_char_p)
        value, quoted, values = ctypes.c_char_p(), ctypes.c_int(), []
        while True:
            res = self.lib.av_list_next(ctypes.byref(cursor), ctypes.byref(value), ctypes.byref(quoted))
            if res < 0:
                return None
            if res == 0:
                return values
            values.append(value.value.decode())

    def encode(self, values):
        """The list of av_add_quoted(), or None if it refuses a value."""
        ac = self.lib.av_new(None, None)
        try:
            for v in values:
                b = v.encode()
                if self.lib.av_add_quoted(ac, AV_A_TACMEMBER, b, len(b)):
                    return None
            r = self.lib.av_get(ac, AV_A_TACMEMBER)
            return r.decode() if r is not None else ""
        finally:
            self.lib.av_free(ac)

    def test_decoder(self):
        for text, values in LISTS:
            with self.subTest(text=text):
                self.assertEqual(self.decode(text), values)
                self.assertEqual(self.lib.av_list_check(text.encode(), 0), -1 if values is None else 0)

    def test_quoted_only(self):
        for text, res in (('"a","b"', 0), ('"a",b', -1), ("a", -1), ("", 0)):
            with self.subTest(text=text):
                self.assertEqual(self.lib.av_list_check(text.encode(), 1), res)

    def test_round_trip(self):
        for value in VALUES:
            with self.subTest(value=value):
                self.assertEqual(self.decode(self.encode([value])), [value])
        self.assertEqual(self.decode(self.encode(VALUES)), list(VALUES))
        self.assertEqual(self.encode(['a"b', "c\\d"]), r'"a\"b","c\d"')

    def test_encoder_after_an_empty_value(self):
        """An attribute that is empty or only blanks is a list without values: the first value has no comma before it."""
        for old in (b"", b" \t"):
            with self.subTest(old=old):
                ac = self.lib.av_new(None, None)
                self.lib.av_set(ac, AV_A_TACMEMBER, old)
                self.assertEqual(self.lib.av_add_quoted(ac, AV_A_TACMEMBER, b"ops", 3), 0)
                self.assertEqual(self.lib.av_get(ac, AV_A_TACMEMBER), b'"ops"')
                self.lib.av_free(ac)

    def test_encoder_refuses_values_the_list_cannot_carry(self):
        for value in REFUSED:
            with self.subTest(value=value):
                self.assertIsNone(self.encode([value]))
        b = b"a\0b"
        ac = self.lib.av_new(None, None)
        self.assertEqual(self.lib.av_add_quoted(ac, AV_A_TACMEMBER, b, len(b)), -1)
        self.lib.av_free(ac)


if __name__ == "__main__":
    unittest.main()
