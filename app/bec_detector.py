"""
Business Email Compromise (BEC) — purpose-built pattern detectors.
The PS specifically calls out: "payment diversion, fake invoice requests,
credential harvesting attempts, and executive impersonation." Our existing
urgency-phrase scorer is generic; these detectors target BEC specifically.
"""

import re

EXECUTIVE_TITLES = [
    "ceo", "cfo", "coo", "cto", "president", "chairman", "founder",
    "managing director", "chief executive", "chief financial",
    "vice president", "vp of finance", "director of finance",
]

PAYMENT_DIVERSION_PHRASES = [
    "update your bank details", "change of payment account", "new account details",
    "remit payment to", "wire transfer", "banking information has changed",
    "beneficiary account", "swift code", "iban", "new payment instructions",
    "kindly process payment", "process the payment immediately",
    "urgent wire", "outstanding invoice attached",
]

CREDENTIAL_HARVESTING_PHRASES = [
    "reset your password", "confirm your credentials", "login to verify",
    "your session has expired", "re-enter your password", "verify your login",
]


def detect_executive_impersonation(identity, body_text):
    """
    Flags when the sender's DISPLAY NAME claims an executive title —
    a hallmark BEC pattern ("Hi, this is the CEO, I need you to...").
    """
    from_header = identity.get("from", "") or ""
    display_name_match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    display_name = display_name_match.group(1).lower() if display_name_match else from_header.lower()

    matched_titles = [title for title in EXECUTIVE_TITLES if title in display_name]

    if matched_titles:
        return {
            "matched_titles": matched_titles,
            "display_name": display_name.strip(),
        }
    return None


def detect_payment_diversion(body_text):
    """Flags language associated with redirecting payments or changing banking details."""
    body_lower = (body_text or "").lower()
    matched = [phrase for phrase in PAYMENT_DIVERSION_PHRASES if phrase in body_lower]
    return matched if matched else None


def detect_credential_harvesting(body_text):
    """Flags language designed to trick the recipient into re-entering login credentials."""
    body_lower = (body_text or "").lower()
    matched = [phrase for phrase in CREDENTIAL_HARVESTING_PHRASES if phrase in body_lower]
    return matched if matched else None


def analyze_bec_patterns(identity, body_text):
    """Run all three BEC-specific checks and return combined findings."""
    return {
        "executive_impersonation": detect_executive_impersonation(identity, body_text),
        "payment_diversion": detect_payment_diversion(body_text),
        "credential_harvesting": detect_credential_harvesting(body_text),
    }


if __name__ == "__main__":
    identity1 = {"from": '"John Smith, CEO" <j.smith@totally-legit-corp-secure.com>'}
    body1 = "Please process the payment immediately to our new account details attached. This is urgent, keep it confidential."
    print("Test 1 (CEO fraud):", analyze_bec_patterns(identity1, body1))

    identity2 = {"from": "Newsletter <news@legit-company.com>"}
    body2 = "Here's our monthly newsletter with product updates."
    print("Test 2 (normal):", analyze_bec_patterns(identity2, body2))

    identity3 = {"from": "IT Support <it@company.com>"}
    body3 = "Your session has expired. Please login to verify your account."
    print("Test 3 (credential harvesting):", analyze_bec_patterns(identity3, body3))