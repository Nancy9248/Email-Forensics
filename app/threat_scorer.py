"""
Fraud scoring engine — combines every signal we've built so far:
  - SPF/DKIM/DMARC authentication failures
  - From/Reply-To identity mismatches
  - Urgency/pressure language (rule-based)
  - ML classifier prediction on the email body (real trained model)
  - Domain lookalike + link mismatch detection
  - Attachment risk flags
  - Return-Path/From domain mismatch
  - Relay timestamp anomalies (forged/reordered headers)
  - VPN/proxy/hosting infrastructure flags
  - Domain age (WHOIS) and MX/DNS validity
  - Identity correlation (repeat domains/IPs, graph-linked campaigns)
  - Message-ID domain mismatch
  - External threat intelligence (Spamhaus DROP, Tor exit nodes)

Every point is traceable to a specific reason.
"""

import re
import os
import joblib

from link_analysis import analyze_links, check_domain_lookalike, extract_domain
from header_analysis import check_return_path_mismatch, check_relay_timestamp_anomalies, check_message_id_mismatch
from threat_intel import check_ip_reputation
from bec_detector import analyze_bec_patterns

URGENCY_PHRASES = [
    "urgent", "immediately", "verify your identity", "account has been limited",
    "suspended", "act now", "click here", "within 24 hours", "confirm your",
    "unusual activity", "unauthorized access", "overdue", "immediate payment",
]

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

_ml_model = None
_ml_vectorizer = None


def _load_ml_model():
    global _ml_model, _ml_vectorizer
    if _ml_model is not None:
        return _ml_model, _ml_vectorizer

    model_path = os.path.join(MODEL_DIR, "phishing_classifier.joblib")
    vectorizer_path = os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib")

    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        _ml_model = joblib.load(model_path)
        _ml_vectorizer = joblib.load(vectorizer_path)
    else:
        _ml_model, _ml_vectorizer = False, False

    return _ml_model, _ml_vectorizer


def score_auth_results(auth_results):
    reasons = []
    points = 0

    if auth_results.get("spf") == "fail":
        points += 30
        reasons.append("SPF check failed — sender IP not authorized for this domain (+30)")

    if auth_results.get("dkim") in ("fail", "none"):
        points += 20
        reasons.append("DKIM missing or invalid — no cryptographic proof of authenticity (+20)")

    if auth_results.get("dmarc") == "fail":
        points += 25
        reasons.append("DMARC check failed — domain policy violated (+25)")

    return points, reasons


def score_identity_mismatch(identity):
    reasons = []
    points = 0

    from_addr = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", identity.get("from", "") or "")
    reply_to_addr = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", identity.get("reply_to", "") or "")

    if from_addr and reply_to_addr and from_addr.group().lower() != reply_to_addr.group().lower():
        points += 15
        reasons.append(f"Reply-To ({reply_to_addr.group()}) differs from From ({from_addr.group()}) (+15)")

    return points, reasons


def score_body_content(body_text):
    reasons = []
    points = 0
    body_lower = (body_text or "").lower()

    found_phrases = [phrase for phrase in URGENCY_PHRASES if phrase in body_lower]
    if found_phrases:
        phrase_points = min(len(found_phrases) * 5, 20)
        points += phrase_points
        reasons.append(f"Urgency/pressure language detected: {', '.join(found_phrases[:3])} (+{phrase_points})")

    return points, reasons


def score_ml_classification(body_text):
    reasons = []
    points = 0

    model, vectorizer = _load_ml_model()
    if not model or not body_text:
        return points, reasons

    vector = vectorizer.transform([body_text])
    phishing_probability = model.predict_proba(vector)[0][1]

    if phishing_probability >= 0.5:
        ml_points = round(phishing_probability * 25)
        points += ml_points
        reasons.append(
            f"ML classifier flagged body text as phishing with {phishing_probability:.0%} confidence (+{ml_points})"
        )

    return points, reasons


def score_sender_domain(identity):
    reasons = []
    points = 0

    from_domain = extract_domain(identity.get("from", "") or "")
    lookalike = check_domain_lookalike(from_domain)
    if lookalike:
        points += 20
        reasons.append(
            f"Sender domain '{lookalike['full_domain']}' closely resembles "
            f"'{lookalike['suspected_target_brand']}' (+20)"
        )

    return points, reasons


def score_links(body_html):
    reasons = []
    points = 0

    flagged_links = analyze_links(body_html)
    if flagged_links:
        link_points = min(len(flagged_links) * 10, 20)
        points += link_points
        for link in flagged_links[:2]:
            reasons.append(f"Suspicious link ({link['actual_domain']}): {link['issues'][0]} (+{link_points // len(flagged_links)})")

    return points, reasons


def score_attachments(attachments):
    reasons = []
    points = 0

    for attachment in attachments or []:
        if attachment.get("is_risky_extension"):
            points += 25
            reasons.append(f"Attachment '{attachment['filename']}' has a high-risk executable extension (+25)")
        elif attachment.get("is_macro_enabled"):
            points += 15
            reasons.append(f"Attachment '{attachment['filename']}' supports macros, a common malware vector (+15)")

        if attachment.get("is_double_extension") and attachment.get("is_risky_extension"):
            points += 10
            reasons.append(f"Attachment '{attachment['filename']}' uses a disguised double extension (+10)")

    return points, reasons


def score_return_path(identity):
    reasons = []
    points = 0

    mismatch = check_return_path_mismatch(identity)
    if mismatch:
        points += 15
        reasons.append(
            f"Return-Path domain ('{mismatch['return_path_domain']}') differs from "
            f"From domain ('{mismatch['from_domain']}') (+15)"
        )

    return points, reasons


def score_timestamp_anomalies(received_chain):
    reasons = []
    points = 0

    anomalies = check_relay_timestamp_anomalies(received_chain)
    if anomalies:
        points += 20
        first = anomalies[0]
        reasons.append(
            f"Relay timestamp anomaly: hop {first['hop_number']} timestamp is "
            f"{abs(first['time_difference_seconds']):.0f}s earlier than hop "
            f"{first['previous_hop_number']} — possible forged header (+20)"
        )

    return points, reasons


def score_infrastructure(geolocation):
    reasons = []
    points = 0

    if not geolocation or geolocation.get("error"):
        return points, reasons

    if geolocation.get("is_proxy_or_vpn"):
        points += 15
        reasons.append("Originating IP is a known VPN/proxy/Tor exit node (+15)")

    if geolocation.get("is_hosting_provider"):
        points += 10
        reasons.append("Originating IP belongs to a hosting/data-center provider, not a residential/business ISP (+10)")

    return points, reasons


def score_domain_intelligence(domain_info):
    reasons = []
    points = 0

    if not domain_info:
        return points, reasons

    whois_info = domain_info.get("whois", {})
    if whois_info.get("is_newly_registered"):
        age = whois_info.get("domain_age_days")
        points += 20
        reasons.append(f"Sender domain was registered only {age} days ago — newly registered domains are a common phishing pattern (+20)")

    dns_info = domain_info.get("dns", {})
    if dns_info.get("error") == "Domain does not exist":
        points += 15
        reasons.append("Sender domain does not appear to exist (no DNS record found) (+15)")
    elif not dns_info.get("has_mx_records") and not dns_info.get("error"):
        points += 5
        reasons.append("Sender domain has no mail server (MX) records configured (+5)")

    return points, reasons


def score_correlation(correlation_result):
    reasons = []
    points = 0

    if not correlation_result:
        return points, reasons

    if correlation_result.get("same_domain_count", 0) > 0:
        count = correlation_result["same_domain_count"]
        points += 15
        reasons.append(f"Sender domain has appeared in {count} previous case(s) in this system (+15)")
    elif correlation_result.get("same_ip_count", 0) > 0:
        count = correlation_result["same_ip_count"]
        points += 10
        reasons.append(f"Originating IP has appeared in {count} previous case(s) in this system (+10)")

    linked = correlation_result.get("linked_entities", [])
    if linked:
        points += 15
        examples = ", ".join(linked[:3])
        reasons.append(f"Linked via shared infrastructure to other known case(s): {examples} — possible coordinated campaign (+15)")

    return points, reasons


def score_message_id(identity):
    reasons = []
    points = 0

    result = check_message_id_mismatch(identity)
    if result:
        if result["issue"] == "mismatch":
            points += 15
            reasons.append(
                f"Message-ID domain ('{result['message_id_domain']}') does not match "
                f"From domain ('{result['from_domain']}') (+15)"
            )
        elif result["issue"] == "missing":
            points += 5
            reasons.append("Message-ID header is missing entirely — unusual for legitimate mail servers (+5)")

    return points, reasons


def score_threat_intel(originating_ip):
    """
    Check the originating IP against real external threat feeds:
    Spamhaus DROP (known malicious netblocks) and the Tor exit node list.
    """
    reasons = []
    points = 0

    if not originating_ip:
        return points, reasons

    intel = check_ip_reputation(originating_ip)

    if intel.get("in_spamhaus_drop"):
        points += 25
        reasons.append(
            f"Originating IP falls within a Spamhaus DROP netblock ({intel['matched_netblock']}) "
            f"— known malicious infrastructure (+25)"
        )

    if intel.get("is_tor_exit_node"):
        points += 15
        reasons.append("Originating IP is a confirmed Tor exit node (+15)")

    return points, reasons

def score_bec_patterns(identity, body_text):
    """
    Business Email Compromise specific signals: executive impersonation,
    payment diversion requests, and credential harvesting language.
    """
    reasons = []
    points = 0

    bec = analyze_bec_patterns(identity, body_text)

    if bec["executive_impersonation"]:
        titles = ", ".join(bec["executive_impersonation"]["matched_titles"])
        points += 20
        reasons.append(f"Sender display name claims an executive title ({titles}) — classic BEC impersonation pattern (+20)")

    if bec["payment_diversion"]:
        matched = ", ".join(bec["payment_diversion"][:3])
        points += 20
        reasons.append(f"Payment diversion / fake invoice language detected: {matched} (+20)")

    if bec["credential_harvesting"]:
        matched = ", ".join(bec["credential_harvesting"][:3])
        points += 10
        reasons.append(f"Credential harvesting language detected: {matched} (+10)")

    return points, reasons

def get_verdict(score):
    if score >= 60:
        return "Malicious"
    elif score >= 30:
        return "Suspicious"
    else:
        return "Safe"


def score_email(parsed_result, geolocation=None, domain_info=None, correlation_result=None):
    """
    Takes the full output of parser.py (parsed_result), plus optional
    geolocation and domain_info, and returns a fraud score, verdict,
    and the list of reasons behind it.
    """
    total_score = 0
    all_reasons = []

    for scoring_function, args in [
        (score_auth_results, (parsed_result["auth_results"],)),
        (score_identity_mismatch, (parsed_result["identity"],)),
        (score_body_content, (parsed_result["body_text"],)),
        (score_ml_classification, (parsed_result["body_text"],)),
        (score_sender_domain, (parsed_result["identity"],)),
        (score_links, (parsed_result.get("body_html", ""),)),
        (score_attachments, (parsed_result.get("attachments", []),)),
        (score_return_path, (parsed_result["identity"],)),
        (score_timestamp_anomalies, (parsed_result["received_chain"],)),
        (score_message_id, (parsed_result["identity"],)),
        (score_threat_intel, (parsed_result["originating_ip"],)),
        (score_bec_patterns, (parsed_result["identity"], parsed_result["body_text"])),
        (score_infrastructure, (geolocation,)),
        (score_domain_intelligence, (domain_info,)),
        (score_correlation, (correlation_result,)),
    ]:
        pts, reasons = scoring_function(*args)
        total_score += pts
        all_reasons += reasons

    total_score = min(total_score, 100)

    return {
        "score": total_score,
        "verdict": get_verdict(total_score),
        "reasons": all_reasons,
    }