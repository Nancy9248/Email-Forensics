"""
Header & Protocol Analysis Module.
Two forensic checks the PS calls out specifically that go beyond basic
SPF/DKIM/DMARC:

1. Return-Path / From domain mismatch — the Return-Path is where bounce
   messages go, and legitimate mail almost always has it match (or be a
   clear sub-domain of) the From address. A mismatch suggests the sender
   is routing bounces somewhere other than where the mail claims to be from.

2. Relay-timestamp anomaly detection — each hop in the Received chain
   should have a timestamp EQUAL TO OR LATER than the hop before it
   (since time moves forward as an email travels through servers).
   A timestamp that goes backward suggests a forged or manually
   inserted/reordered Received header — a sign of tampering.
"""

from datetime import datetime, timedelta
from link_analysis import extract_domain
import re

CLOCK_SKEW_TOLERANCE = timedelta(seconds=5)


def check_return_path_mismatch(identity):
    """
    Compare the From domain against the Return-Path domain.
    Returns a finding dict if they differ, otherwise None.
    """
    from_domain = extract_domain(identity.get("from", "") or "")
    return_path_domain = extract_domain(identity.get("return_path", "") or "")

    if not from_domain or not return_path_domain:
        return None

    if from_domain != return_path_domain:
        return {
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
        }
    return None


def check_relay_timestamp_anomalies(received_chain):
    """
    Walk the Received chain in chronological order and flag any hop whose
    timestamp is EARLIER than the previous hop's, beyond clock-skew tolerance.
    """
    anomalies = []
    previous_hop = None

    for hop in received_chain:
        if not hop.get("timestamp"):
            previous_hop = hop
            continue

        current_time = datetime.fromisoformat(hop["timestamp"])

        if previous_hop and previous_hop.get("timestamp"):
            previous_time = datetime.fromisoformat(previous_hop["timestamp"])

            if current_time < previous_time - CLOCK_SKEW_TOLERANCE:
                anomalies.append({
                    "hop_number": hop["hop_number"],
                    "previous_hop_number": previous_hop["hop_number"],
                    "current_timestamp": hop["timestamp"],
                    "previous_timestamp": previous_hop["timestamp"],
                    "time_difference_seconds": (current_time - previous_time).total_seconds(),
                })

        previous_hop = hop

    return anomalies

def check_message_id_mismatch(identity):
    """
    A Message-ID looks like <unique-string@domain.com>. Legitimate mail
    servers generate this using the SENDING domain's own infrastructure,
    so it should match the From domain. A mismatch or missing Message-ID
    is a forgery signal.
    """
    message_id = identity.get("message_id", "") or ""
    from_domain = extract_domain(identity.get("from", "") or "")

    if not message_id:
        return {"issue": "missing", "from_domain": from_domain}

    match = re.search(r"@([\w.-]+)>?$", message_id.strip())
    if not match:
        return {"issue": "unparseable", "from_domain": from_domain, "message_id": message_id}

    message_id_domain = match.group(1).lower()

    if from_domain and message_id_domain != from_domain and not message_id_domain.endswith("." + from_domain):
        return {
            "issue": "mismatch",
            "from_domain": from_domain,
            "message_id_domain": message_id_domain,
        }

    return None

def analyze_headers(parsed_result):
    """Runs both header/protocol checks and returns a combined findings dict."""
    return {
        "return_path_mismatch": check_return_path_mismatch(parsed_result["identity"]),
        "timestamp_anomalies": check_relay_timestamp_anomalies(parsed_result["received_chain"]),
    }


if __name__ == "__main__":
    matching_identity = {
        "from": "PayPal Security <accounts@paypa1-secure.com>",
        "return_path": "<accounts@paypa1-secure.com>",
    }
    print("Matching identity test:", check_return_path_mismatch(matching_identity))

    mismatched_identity = {
        "from": "PayPal Security <accounts@paypal.com>",
        "return_path": "<bounces@totally-different-domain.ru>",
    }
    print("Mismatched identity test:", check_return_path_mismatch(mismatched_identity))

    normal_chain = [
        {"hop_number": 1, "timestamp": "2026-09-11T10:00:00+00:00"},
        {"hop_number": 2, "timestamp": "2026-09-11T10:00:05+00:00"},
        {"hop_number": 3, "timestamp": "2026-09-11T10:00:10+00:00"},
    ]
    print("Normal chain anomalies:", check_relay_timestamp_anomalies(normal_chain))

    tampered_chain = [
        {"hop_number": 1, "timestamp": "2026-09-11T10:00:00+00:00"},
        {"hop_number": 2, "timestamp": "2026-09-11T09:55:00+00:00"},
        {"hop_number": 3, "timestamp": "2026-09-11T10:00:10+00:00"},
    ]
    print("Tampered chain anomalies:", check_relay_timestamp_anomalies(tampered_chain))