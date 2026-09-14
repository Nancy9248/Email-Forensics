"""
Detects two classic phishing techniques:
1. Domain lookalikes — e.g. "paypa1-secure.com" impersonating "paypal.com"
2. Link/anchor mismatches — link text claims one domain, but actually points elsewhere

Fixed version: compares individual domain TOKENS (split on '.', '-') against
known brand names, instead of comparing the whole domain string. This is why
the first version missed "paypa1-secure.com" — comparing that entire 18-character
string to "paypal.com" dilutes the similarity score. Comparing just the token
"paypa1" against "paypal" catches it correctly.
"""

import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple", "netflix",
    "facebook", "instagram", "chase", "bankofamerica", "wellsfargo",
    "irs", "dhl", "fedex", "outlook", "linkedin",
]

LINK_PATTERN = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
URL_IN_TEXT_PATTERN = re.compile(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,})')


def extract_domain(email_address_or_url):
    """Pull just the domain out of an email address or a URL."""
    if not email_address_or_url:
        return ""
    if "@" in email_address_or_url:
        return email_address_or_url.split("@")[-1].strip("> ").lower()
    parsed = urlparse(email_address_or_url if "://" in email_address_or_url else f"//{email_address_or_url}")
    return (parsed.hostname or "").lower()


def _domain_tokens(domain):
    """Split a domain into its meaningful parts: 'paypa1-secure.com' -> ['paypa1', 'secure', 'com']"""
    return [t for t in re.split(r"[.\-]", domain) if t]


def check_domain_lookalike(domain):
    """
    Compare each token of the domain against known brand names.
    A token that closely matches a brand (but isn't an exact match to that
    brand's own real domain) is a lookalike red flag.
    """
    if not domain:
        return None

    tokens = _domain_tokens(domain)
    best_match = None
    best_ratio = 0
    best_token = None

    for token in tokens:
        for brand in KNOWN_BRANDS:
            ratio = SequenceMatcher(None, token, brand).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_match = brand
                best_token = token

    if best_match and best_token != best_match and best_ratio >= 0.8:
        return {
            "suspected_target_brand": best_match,
            "suspicious_token": best_token,
            "similarity": round(best_ratio, 2),
            "full_domain": domain,
        }
    return None


def extract_links(html_body):
    """Find all <a> tags and return (href, visible_text) pairs."""
    return LINK_PATTERN.findall(html_body or "")


def analyze_links(html_body):
    """
    Full link analysis: for every link in the email body, check:
    1. Does the link's OWN destination domain look like a brand lookalike?
    2. Does the visible anchor text claim a different domain than the href?
    Returns a list of flagged links with the reason for each flag.
    """
    flagged = []

    for href, visible_text in extract_links(html_body):
        href_domain = extract_domain(href)
        issues = []

        lookalike = check_domain_lookalike(href_domain)
        if lookalike:
            issues.append(f"Link destination domain '{href_domain}' resembles '{lookalike['suspected_target_brand']}'")

        text_domain_match = URL_IN_TEXT_PATTERN.search(visible_text)
        if text_domain_match:
            claimed_domain = text_domain_match.group(1).lower()
            if claimed_domain not in href_domain and href_domain not in claimed_domain:
                issues.append(f"Visible text claims '{claimed_domain}' but link actually goes to '{href_domain}'")

        if issues:
            flagged.append({
                "visible_text": visible_text.strip(),
                "actual_destination": href,
                "actual_domain": href_domain,
                "issues": issues,
            })

    return flagged


if __name__ == "__main__":
    print("Sender domain lookalike:", check_domain_lookalike("paypa1-secure.com"))
    
    sample_html = '<a href="http://paypa1-secure-verify.com/login?id=8842">click here to verify your identity</a>'
    print("Flagged links:", analyze_links(sample_html))

    deceptive_html = '<a href="http://totally-different-site.ru/x">www.paypal.com/login</a>'
    print("Flagged links (text mismatch):", analyze_links(deceptive_html))