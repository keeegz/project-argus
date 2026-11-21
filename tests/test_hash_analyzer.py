
from argus.hash_analyzer import identify_hash_type


def test_md5_hash():
    assert identify_hash_type("a" * 32) == "MD5"


def test_sha1_hash():
    assert identify_hash_type("b" * 40) == "SHA-1"


def test_sha256_hash():
    assert identify_hash_type("c" * 64) == "SHA-256"


def test_invalid_hash():
    assert identify_hash_type("not_a_valid_hash") == "Invalid"


def test_invalid_length():
    assert identify_hash_type("abc123") == "Invalid"
