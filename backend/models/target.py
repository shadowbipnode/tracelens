import ipaddress
import re

from pydantic import BaseModel, field_validator


DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def validate_domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("target must be a domain")

    target = value.strip().lower()
    if target != value.lower() or not target:
        raise ValueError("target must not contain surrounding whitespace")
    if len(target) > 253:
        raise ValueError("target is too long")
    if "://" in target:
        raise ValueError("target must be a domain without a URL scheme")
    if any(character in target for character in "/?#@:\\"):
        raise ValueError("target must not contain URL or path components")
    if "." not in target:
        raise ValueError("target must be a fully qualified domain")

    try:
        ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not valid scan targets")

    labels = target.split(".")
    if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("target contains an invalid domain label")
    if labels[-1].isdigit() or len(labels[-1]) < 2:
        raise ValueError("target must have a valid top-level domain")

    return target


class ScanCreate(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def domain_is_valid(cls, value: str) -> str:
        return validate_domain(value)
