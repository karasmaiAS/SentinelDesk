import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from django.core.exceptions import ValidationError


_HASH_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
}
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HEX_VALUE = re.compile(r"^[0-9a-fA-F]+$")


def _normalize_domain(value):
    try:
        domain = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValidationError({"value": "Enter a valid domain name."}) from error
    if not domain or len(domain) > 253:
        raise ValidationError({"value": "Enter a valid domain name."})
    labels = domain.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValidationError({"value": "Enter a valid domain name."})
    return domain


def normalize_indicator(indicator_type, value):
    value = value.strip()
    if not value:
        raise ValidationError({"value": "Enter an indicator value."})

    if indicator_type == "ipv4":
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValidationError({"value": "Enter a valid IPv4 address."}) from error
        if address.version != 4:
            raise ValidationError({"value": "Enter a valid IPv4 address."})
        return str(address)

    if indicator_type == "domain":
        return _normalize_domain(value)

    if indicator_type == "url":
        try:
            parsed = urlsplit(value)
            host = parsed.hostname
            port = parsed.port
        except ValueError as error:
            raise ValidationError({"value": "Enter a valid HTTP or HTTPS URL."}) from error
        if (
            parsed.scheme.lower() not in ("http", "https")
            or not host
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValidationError({"value": "Enter a valid HTTP or HTTPS URL."})
        try:
            normalized_host = str(ipaddress.ip_address(host))
        except ValueError:
            normalized_host = _normalize_domain(host)
        if ":" in normalized_host and not normalized_host.startswith("["):
            normalized_host = f"[{normalized_host}]"
        default_port = (
            port == 80 and parsed.scheme.lower() == "http"
        ) or (port == 443 and parsed.scheme.lower() == "https")
        netloc = normalized_host
        if port is not None and not default_port:
            netloc = f"{netloc}:{port}"
        return urlunsplit(
            (
                parsed.scheme.lower(),
                netloc,
                parsed.path or "/",
                parsed.query,
                "",
            )
        )

    hash_length = _HASH_LENGTHS.get(indicator_type)
    if hash_length is None:
        raise ValidationError({"indicator_type": "Select a valid indicator type."})
    if len(value) != hash_length or not _HEX_VALUE.fullmatch(value):
        raise ValidationError(
            {"value": f"Enter a valid {indicator_type.upper()} file hash."}
        )
    return value.lower()
