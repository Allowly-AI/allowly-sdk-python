import pytest

from allowly.identifiers import from_email, normalize_email


def test_normalize_email_trims_and_lowercases_only():
    assert normalize_email(" John.Doe@Example.COM ") == "john.doe@example.com"
    assert normalize_email("j.o.h.n+sales@gmail.com") == "j.o.h.n+sales@gmail.com"


def test_from_email_returns_versioned_hmac_identifier():
    assert (
        from_email(" John.Doe@Example.COM ", pepper="pepper-secret")
        == "email_hmac:v1:joGNnOl733jVwFo68Eh9yBii-N5CkEOwKDyTFZTKpVI"
    )


def test_from_email_accepts_bytes_pepper():
    assert from_email("user@example.com", pepper=b"pepper").startswith("email_hmac:v1:")


def test_from_email_requires_permanent_pepper():
    with pytest.raises(ValueError, match="pepper"):
        from_email("user@example.com", pepper="")


def test_from_email_rejects_invalid_pepper_type():
    with pytest.raises(TypeError, match="pepper"):
        from_email("user@example.com", pepper=None)  # type: ignore[arg-type]


def test_from_email_rejects_empty_email():
    with pytest.raises(ValueError, match="email"):
        from_email("  ", pepper="pepper")


def test_from_email_rejects_unknown_version():
    with pytest.raises(ValueError, match="version"):
        from_email("user@example.com", pepper="pepper", version="v2")
