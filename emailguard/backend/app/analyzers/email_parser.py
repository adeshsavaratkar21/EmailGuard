from __future__ import annotations

import re
from email import message_from_bytes
from email.header import decode_header
from email.policy import default
from email.utils import getaddresses, parseaddr
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlsplit

_URL_RE = re.compile(r"https?://[^\s<>\"'`()\[\]{}]+", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""


def _decode_header_value(value: object) -> str:
    if value is None:
        return ""
    try:
        pieces = decode_header(str(value))
        return "".join(
            part.decode(charset or "utf-8", errors="replace") if isinstance(part, bytes) else part
            for part, charset in pieces
        ).strip()
    except Exception:
        return str(value).strip()


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.hrefs.append(value.strip())


def _clean_url(candidate: str) -> str | None:
    value = unescape(candidate.strip())
    while value and value[-1] in _TRAILING_PUNCTUATION:
        value = value[:-1]
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        return value
    except ValueError:
        return None


def extract_urls(text: str, html_documents: list[str] | None = None) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        normalized = _clean_url(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            found.append(normalized)

    for match in _URL_RE.findall(text or ""):
        add(match)
    for document in html_documents or []:
        parser = _LinkParser()
        try:
            parser.feed(document)
            for href in parser.hrefs:
                add(href)
        except Exception:
            continue
        for match in _URL_RE.findall(document):
            add(match)
    return found


def parse_eml(raw: bytes) -> dict:
    message = message_from_bytes(raw, policy=default)
    from_header = _decode_header_value(message.get("From"))
    _, sender = parseaddr(from_header)
    to_values = [address for _, address in getaddresses(message.get_all("To", [])) if address]
    cc_values = [address for _, address in getaddresses(message.get_all("Cc", [])) if address]
    reply_to = _decode_header_value(message.get("Reply-To"))
    _, reply_address = parseaddr(reply_to)

    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []
    mime_types: list[str] = []

    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart():
            continue
        content_type = part.get_content_type().lower()
        mime_types.append(content_type)
        filename = part.get_filename()
        if filename:
            try:
                decoded = part.get_payload(decode=True) or b""
                byte_size = len(decoded)
            except Exception:
                payload = part.get_payload()
                byte_size = len(payload) if isinstance(payload, bytes) else 0
            attachments.append({
                "filename": _decode_header_value(filename)[:255],
                "mime_type": content_type,
                "size_bytes": byte_size,
                "inspection": "metadata only; not opened or executed",
            })
            continue
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
            if isinstance(content, bytes):
                content = content.decode(part.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if content_type == "text/html":
            html_parts.append(str(content))
        else:
            plain_parts.append(str(content))

    plain_text = "\n".join(plain_parts)
    html_text = "\n".join(html_parts)
    visible_html_text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html_text)
    visible_html_text = re.sub(r"(?s)<[^>]+>", " ", visible_html_text)
    visible_html_text = unescape(visible_html_text)
    combined_body = "\n".join(part for part in (plain_text, visible_html_text) if part).strip()

    headers = {
        "from": from_header,
        "to": ", ".join(to_values),
        "cc": ", ".join(cc_values),
        "reply_to": reply_to,
        "return_path": _decode_header_value(message.get("Return-Path")),
        "subject": _decode_header_value(message.get("Subject")),
        "date": _decode_header_value(message.get("Date")),
        "message_id": _decode_header_value(message.get("Message-ID")),
        "received": [_decode_header_value(value) for value in message.get_all("Received", [])[:12]],
        "authentication_results": [_decode_header_value(value) for value in message.get_all("Authentication-Results", [])],
        "dkim_signature": _decode_header_value(message.get("DKIM-Signature")),
        "mime_version": _decode_header_value(message.get("MIME-Version")),
    }
    urls = extract_urls("\n".join([plain_text, visible_html_text]), html_parts)
    return {
        "headers": headers,
        "sender": sender or from_header,
        "recipients": to_values + cc_values,
        "reply_to_address": reply_address,
        "subject": headers["subject"],
        "body_text": combined_body[:500_000],
        "body_character_count": len(combined_body),
        "mime_types": sorted(set(mime_types)),
        "attachments": attachments,
        "urls": urls,
        "raw_message_size": len(raw),
    }
