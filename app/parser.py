"""
Core email forensic parser.
Given a .eml file, extracts:
  - the full Received chain (in true chronological order), including timestamps
  - the real originating IP (earliest hop)
  - SPF / DKIM / DMARC verdicts
  - identity fields (From, Reply-To, Return-Path) for mismatch checks
  - the plain-text body content (for threat scoring)
  - the raw HTML body (for link analysis)
  - attachment metadata (filename, type, size) for risk flagging
"""

import re
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HTML_TAG_PATTERN = re.compile(r"<[^>]+>")

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jar", ".ps1", ".msi", ".dll", ".hta", ".wsf",
}
MACRO_ENABLED_EXTENSIONS = {".docm", ".xlsm", ".pptm"}


def load_email(file_path):
    with open(file_path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def _extract_hop_timestamp(raw_header):
    """
    A Received header's timestamp is the part after the LAST semicolon,
    e.g. '...; Thu, 11 Sep 2026 10:14:15 +0000 (UTC)'.
    Returns a timezone-aware datetime, or None if it can't be parsed.
    """
    if ";" not in raw_header:
        return None
    date_part = raw_header.rsplit(";", 1)[-1].strip()
    try:
        return parsedate_to_datetime(date_part)
    except (TypeError, ValueError):
        return None


def get_received_chain(message):
    received_headers = message.get_all("Received", [])
    chain = list(reversed(received_headers))  # earliest hop first

    parsed_chain = []
    for i, hop in enumerate(chain):
        raw = str(hop)
        ips_found = IP_PATTERN.findall(raw)
        timestamp = _extract_hop_timestamp(raw)
        parsed_chain.append({
            "hop_number": i + 1,
            "raw": raw,
            "ips_found": ips_found,
            "timestamp": timestamp.isoformat() if timestamp else None,
        })
    return parsed_chain


def get_originating_ip(received_chain):
    if not received_chain:
        return None
    first_hop = received_chain[0]
    if first_hop["ips_found"]:
        return first_hop["ips_found"][0]
    return None


def get_auth_results(message):
    auth_header = message.get("Authentication-Results", "")
    results = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", str(auth_header), re.IGNORECASE)
        results[mechanism] = match.group(1).lower() if match else "not_found"
    return results


def get_identity_fields(message):
    return {
        "from": message.get("From", ""),
        "reply_to": message.get("Reply-To", ""),
        "return_path": message.get("Return-Path", ""),
        "x_originating_ip": message.get("X-Originating-IP", ""),
        "message_id": message.get("Message-ID", ""),
    }


def get_body_text_and_html(message):
    plain_body = None
    html_body = None

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" and plain_body is None:
                plain_body = part.get_content()
            elif content_type == "text/html" and html_body is None:
                html_body = part.get_content()
    else:
        content_type = message.get_content_type()
        if content_type == "text/plain":
            plain_body = message.get_content()
        elif content_type == "text/html":
            html_body = message.get_content()

    clean_text = None
    if plain_body:
        clean_text = plain_body.strip()
    elif html_body:
        clean_text = HTML_TAG_PATTERN.sub(" ", html_body).strip()

    return clean_text or "", html_body or ""


def get_attachments(message):
    attachments = []

    if not message.is_multipart():
        return attachments

    for part in message.walk():
        content_disposition = part.get_content_disposition()
        if content_disposition == "attachment":
            filename = part.get_filename() or "unnamed_attachment"
            content_type = part.get_content_type()

            try:
                payload_size = len(part.get_payload(decode=True) or b"")
            except Exception:
                payload_size = 0

            extension_match = re.search(r"(\.\w+)(\.\w+)?$", filename.lower())
            extensions_found = [g for g in (extension_match.groups() if extension_match else []) if g]

            is_risky = any(ext in RISKY_EXTENSIONS for ext in extensions_found)
            is_macro_enabled = any(ext in MACRO_ENABLED_EXTENSIONS for ext in extensions_found)
            is_double_extension = len(extensions_found) >= 2

            attachments.append({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": payload_size,
                "is_risky_extension": is_risky,
                "is_macro_enabled": is_macro_enabled,
                "is_double_extension": is_double_extension,
            })

    return attachments


def parse_email_file(file_path):
    message = load_email(file_path)
    received_chain = get_received_chain(message)
    body_text, body_html = get_body_text_and_html(message)

    return {
        "subject": message.get("Subject", ""),
        "date": message.get("Date", ""),
        "identity": get_identity_fields(message),
        "auth_results": get_auth_results(message),
        "received_chain": received_chain,
        "originating_ip": get_originating_ip(received_chain),
        "body_text": body_text,
        "body_html": body_html,
        "attachments": get_attachments(message),
    }


if __name__ == "__main__":
    import json
    result = parse_email_file("samples/sample_phishing.eml")
    print(json.dumps(result, indent=2))