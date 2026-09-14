"""
One-time test-data generator: creates a classic BEC/CEO-fraud email to
verify bec_detector.py actually fires when it should.
"""

from email.message import EmailMessage

msg = EmailMessage()
msg["From"] = '"Robert Chen, CEO" <r.chen@corp-secure-mail.com>'
msg["To"] = "finance@example-corp.com"
msg["Subject"] = "Urgent wire transfer needed today"
msg["Authentication-Results"] = "mx; spf=fail; dkim=none; dmarc=fail"
msg["Received"] = "from unknown (unknown [91.203.5.10]); Fri, 13 Sep 2026 09:00:00 +0000"

msg.set_content(
    "Hi,\n\n"
    "I need you to process the payment immediately to our new account details "
    "attached below for an urgent wire transfer. Please keep this confidential "
    "and don't discuss with anyone else in the office. I'm in meetings all day "
    "so please just proceed.\n\n"
    "Thanks,\nRobert"
)

with open("samples/bec_test.eml", "wb") as f:
    f.write(msg.as_bytes())

print("Created samples/bec_test.eml")