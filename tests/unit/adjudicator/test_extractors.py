import pytest

from gateway.adjudicator.extractors import canonical_url, extract_keys, keys_for_arg

INVOICE = (
    "Invoice #4471 from Northwind, total $880.00, payable to account ACC-NORTHWIND-01. "
    "Questions: billing@northwind.com or https://Portal.Northwind.com:443/pay?id=4471."
)


def test_extracts_typed_keys_from_document() -> None:
    keys = extract_keys(INVOICE)
    assert {
        "email:billing@northwind.com",
        "host:northwind.com",
        "url:https://portal.northwind.com/pay?id=4471",
        "host:portal.northwind.com",
        "account:ACCNORTHWIND01",
        "amount:880",
    } <= keys


@pytest.mark.parametrize(
    "a, b",
    [
        ("https://API.company.com/v1", "https://api.company.com:443/v1"),
        ("http://api.company.com./x#frag", "http://api.company.com/x"),
        ("https://api.company.com", "https://api.company.com/"),
    ],
)
def test_url_canonicalization(a: str, b: str) -> None:
    assert canonical_url(a) == canonical_url(b)


def test_argument_keys_match_document_keys_after_normalization() -> None:
    keys = extract_keys(INVOICE)
    assert keys_for_arg("account", "acc-northwind-01")[0] in keys
    assert keys_for_arg("number", 880.0)[0] in keys
    assert keys_for_arg("email", "Billing@Northwind.com")[0] in keys


def test_homoglyph_email_normalizes_to_latin() -> None:
    # Cyrillic "а" in the argument must not dodge a match against the Latin original
    assert (
        keys_for_arg("email", "billing@northwind.com")[0]
        == keys_for_arg("email", "billing@northwіnd.com".replace("і", "i"))[0]
    )
    assert keys_for_arg("email", "pаy@evil.io") == ["email:pay@evil.io"]


def test_grouped_iban_and_thousands_amounts() -> None:
    keys = extract_keys("Wire $1,250.50 to DE89 3704 0044 0532 0130 00 today.")
    assert "amount:1250.5" in keys
    assert "account:DE89370400440532013000" in keys


def test_url_arg_yields_url_then_host() -> None:
    assert keys_for_arg("url", "https://hooks.company.com/a") == [
        "url:https://hooks.company.com/a",
        "host:hooks.company.com",
    ]
    assert keys_for_arg("url", "ftp://nope") == []
