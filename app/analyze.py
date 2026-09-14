"""
Combines the parser, geolocation, domain intelligence, identity
correlation, fraud scoring, and chain-of-custody modules into one
end-to-end analysis. This is the function the Flask API calls.
"""

import json
import os
from parser import parse_email_file
from geolocation import geolocate_ip
from domain_intelligence import analyze_domain
from link_analysis import extract_domain
from correlation import find_correlations
from case_db import init_db, save_case, log_audit_event
from threat_scorer import score_email
from privacy import compute_file_hash

init_db()


def analyze_email(file_path):
    """Run full forensic analysis on a .eml file."""
    evidence_hash = compute_file_hash(file_path)

    parsed = parse_email_file(file_path)

    originating_ip = parsed["originating_ip"]
    location = geolocate_ip(originating_ip) if originating_ip else None

    sender_domain = extract_domain(parsed["identity"].get("from", "") or "")
    domain_info = analyze_domain(sender_domain) if sender_domain else None

    correlation_result = find_correlations(sender_domain, originating_ip)

    threat_assessment = score_email(
        parsed,
        geolocation=location,
        domain_info=domain_info,
        correlation_result=correlation_result,
    )

    result = {
        **parsed,
        "geolocation": location,
        "domain_intelligence": domain_info,
        "correlation": correlation_result,
        "threat_assessment": threat_assessment,
        "evidence_hash": evidence_hash,
    }

    case_id = save_case(
        filename=os.path.basename(file_path),
        from_address=parsed["identity"].get("from", ""),
        sender_domain=sender_domain,
        originating_ip=originating_ip,
        fraud_score=threat_assessment["score"],
        verdict=threat_assessment["verdict"],
        full_result=result,
        evidence_hash=evidence_hash,
    )
    result["case_id"] = case_id

    log_audit_event(case_id, "case_analyzed", f"Score {threat_assessment['score']}, verdict {threat_assessment['verdict']}")

    return result


if __name__ == "__main__":
    result = analyze_email("samples/sample_phishing.eml")
    print(json.dumps(result, indent=2))