"""
Privacy, Legal, and Compliance Safeguards.

1. Evidence hashing (chain-of-custody): every analyzed .eml file gets a
   SHA-256 hash computed at analysis time.

2. PII masking: a configurable way to partially redact sender email
   addresses for views/exports where full personal data shouldn't be shown.

3. Configurable retention: raw uploaded email files aren't kept indefinitely —
   they can be purged after a configurable number of days, while the
   forensic case record (score, hash, audit trail) is retained separately.
"""

import hashlib
import re
import os
import time

DEFAULT_RETENTION_DAYS = 90


def compute_file_hash(file_path):
    """Compute the SHA-256 hash of a file's exact byte content."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def mask_email_address(email_address_or_header):
    """
    Partially redact an email address for privacy-conscious display,
    e.g. 'accounts@paypa1-secure.com' -> 'acc***@paypa1-secure.com'.

    Accepts either a bare address OR a full "From:" style header like
    'PayPal Security <accounts@paypa1-secure.com>' — the display name
    is stripped, and only the actual address underneath is shown, masked.
    """
    if not email_address_or_header:
        return email_address_or_header

    match = re.search(r"[\w.+-]+@[\w.-]+", email_address_or_header)
    if not match:
        return email_address_or_header

    email_address = match.group(0)
    local_part, domain = email_address.rsplit("@", 1)

    if len(local_part) <= 3:
        masked_local = local_part[0] + "***"
    else:
        masked_local = local_part[:3] + "***"

    return f"{masked_local}@{domain}"


def cleanup_old_uploads(upload_folder, retention_days=DEFAULT_RETENTION_DAYS):
    """
    Delete uploaded .eml files older than retention_days.
    The forensic CASE RECORD is kept separately in the database for
    chain-of-custody purposes even after the raw file is purged.
    Returns the list of filenames that were deleted.
    """
    if not os.path.exists(upload_folder):
        return []

    cutoff_time = time.time() - (retention_days * 24 * 60 * 60)
    deleted = []

    for filename in os.listdir(upload_folder):
        file_path = os.path.join(upload_folder, filename)
        if os.path.isfile(file_path) and os.path.getmtime(file_path) < cutoff_time:
            os.remove(file_path)
            deleted.append(filename)

    return deleted


if __name__ == "__main__":
    import os as os_test
    sample_path = "samples/sample_phishing.eml"
    if os_test.path.exists(sample_path):
        print("SHA-256 of sample_phishing.eml:", compute_file_hash(sample_path))

    print("Masked (full header):", mask_email_address("PayPal Security <accounts@paypa1-secure.com>"))
    print("Masked (bare address):", mask_email_address("accounts@paypa1-secure.com"))