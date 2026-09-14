"""
One-time test-data generator: creates an email with a deliberate
Return-Path/From mismatch AND a backward-jumping relay timestamp,
so we can verify header_analysis.py actually catches both.
"""

from email.message import EmailMessage

msg = EmailMessage()
msg["From"] = "PayPal Security <accounts@paypal.com>"
msg["Return-Path"] = "<bounces@totally-different-domain.ru>"  # deliberate mismatch
msg["Reply-To"] = "accounts@paypal.com"
msg["Subject"] = "Test: tampered headers"
msg["Authentication-Results"] = "mx; spf=pass; dkim=pass; dmarc=pass"
# Hop 1 (earliest) at 10:00:00, but hop 2 claims 09:55:00 — 5 minutes BACKWARD
msg["Received"] = "from server-a (server-a [1.2.3.4]); Thu, 11 Sep 2026 09:55:00 +0000"
msg["Received"] = "from server-b (server-b [5.6.7.8]); Thu, 11 Sep 2026 10:00:00 +0000"
msg.set_content("This is a test email for header tampering detection.")

with open("samples/tampered_headers.eml", "wb") as f:
    f.write(msg.as_bytes())

print("Created samples/tampered_headers.eml")
