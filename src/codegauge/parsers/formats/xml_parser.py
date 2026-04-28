from __future__ import annotations

from typing import Any
from xml.etree import ElementTree

from ..base import ScannerOutputInvalidError


def parse_xml_document(stdout: str, *, scanner_name: str) -> ElementTree.Element:
    try:
        return ElementTree.fromstring(stdout)
    except ElementTree.ParseError as exc:
        raise ScannerOutputInvalidError(f"invalid {scanner_name} XML output: {exc}") from exc


def require_xml_attrib(element: ElementTree.Element, name: str, *, context: str) -> str:
    value = element.attrib.get(name)
    if value is None or value == "":
        raise ScannerOutputInvalidError(f"{context} attribute '{name}' must be present")
    return value


def parse_float(value: Any, *, context: str) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError as exc:
            raise ScannerOutputInvalidError(f"{context} must be numeric") from exc
    raise ScannerOutputInvalidError(f"{context} must be numeric")


def parse_int(value: Any, *, context: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError as exc:
            raise ScannerOutputInvalidError(f"{context} must be integer") from exc
    raise ScannerOutputInvalidError(f"{context} must be integer")

