"""Intentionally vulnerable SSRF/XXE examples for local SAST testing only."""

from urllib.parse import urlparse

import requests
from lxml import etree


def fetch_url_vulnerable(url):
    return requests.get(url, timeout=10).text


def fetch_url_allowlisted(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Unsupported scheme")
    if parsed.hostname not in {"api.example.test", "cdn.example.test"}:
        raise ValueError("Domain not allowed")
    return requests.get(url, timeout=10).text


def parse_xml_vulnerable(xml_content):
    parser = etree.XMLParser()
    root = etree.fromstring(xml_content.encode(), parser)
    return etree.tostring(root)


def parse_xml_secure(xml_content):
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(xml_content.encode(), parser)
    return etree.tostring(root)
