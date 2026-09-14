"""
Origin Traceability — Domain Intelligence Module.
Two checks:
1. WHOIS lookup — when was this domain registered? A domain registered
   days or weeks ago is a major phishing red flag (attackers register
   throwaway domains right before a campaign). Legitimate brands' domains
   are usually years or decades old.
2. MX/DNS record check — does this domain even have valid mail server
   records? A domain claiming to send email but with no MX records is
   suspicious (though not conclusive on its own, since the sending
   infrastructure may differ from the claimed domain).

WHOIS uses an old, non-HTTP network protocol and can be slow or
unresponsive for some registrars — so we run it with a hard timeout
using a background thread, to guarantee it never hangs the Flask app.
"""

import dns.resolver
import whois
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

WHOIS_TIMEOUT_SECONDS = 6
NEWLY_REGISTERED_THRESHOLD_DAYS = 60  # domains younger than this are flagged


def _run_whois_query(domain):
    """Raw WHOIS call — run inside a thread so we can enforce a timeout on it."""
    return whois.whois(domain)


def whois_lookup(domain):
    """
    Returns a dict with registrar, creation_date, and computed domain age.
    On any failure (timeout, unsupported TLD, rate limiting), returns a
    dict with an "error" key instead of raising — this must never crash
    the analysis pipeline.
    """
    if not domain:
        return {"error": "No domain provided"}

    # IMPORTANT: we do NOT use "with ThreadPoolExecutor() as executor" here —
    # that context manager waits for the background thread to finish on exit,
    # which would silently cancel our timeout. Instead we shut it down with
    # wait=False, so a slow WHOIS server can't hang the whole app.
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(_run_whois_query, domain)
        result = future.result(timeout=WHOIS_TIMEOUT_SECONDS)
    except FutureTimeoutError:
        return {"error": "WHOIS lookup timed out"}
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}
    finally:
        executor.shutdown(wait=False)

    creation_date = result.creation_date
    if isinstance(creation_date, list):
        creation_date = min((d for d in creation_date if d), default=None)

    domain_age_days = None
    is_newly_registered = None
    if creation_date:
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        domain_age_days = (datetime.now(timezone.utc) - creation_date).days
        is_newly_registered = domain_age_days < NEWLY_REGISTERED_THRESHOLD_DAYS

    registrar = result.registrar
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None

    return {
        "domain": domain,
        "registrar": registrar,
        "creation_date": creation_date.isoformat() if creation_date else None,
        "domain_age_days": domain_age_days,
        "is_newly_registered": is_newly_registered,
    }


def mx_lookup(domain):
    """
    Check for valid MX (mail exchange) records on the domain.
    Returns a dict with the MX hosts found, or an explanation if none exist.
    """
    if not domain:
        return {"has_mx_records": False, "mx_hosts": [], "error": "No domain provided"}

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_hosts = [str(r.exchange).rstrip(".") for r in answers]
        return {"has_mx_records": True, "mx_hosts": mx_hosts}
    except dns.resolver.NXDOMAIN:
        return {"has_mx_records": False, "mx_hosts": [], "error": "Domain does not exist"}
    except dns.resolver.NoAnswer:
        return {"has_mx_records": False, "mx_hosts": [], "error": "No MX records found"}
    except Exception as e:
        return {"has_mx_records": False, "mx_hosts": [], "error": f"DNS lookup failed: {e}"}


def analyze_domain(domain):
    """Combined domain intelligence: WHOIS + MX/DNS, for one sender domain."""
    return {
        "whois": whois_lookup(domain),
        "dns": mx_lookup(domain),
    }


if __name__ == "__main__":
    import json
    print("--- google.com ---")
    print(json.dumps(analyze_domain("google.com"), indent=2))

    print("\n--- paypa1-secure.com (our fake sample domain) ---")
    print(json.dumps(analyze_domain("paypa1-secure.com"), indent=2))