"""
One-time utility script: builds a realistic-looking phishing email WITH
a malicious-looking attachment (a fake .exe disguised as an invoice),
so we have something real to test attachment risk detection against.
This is NOT part of the main app — just a test-data generator.
"""

from email.message import EmailMessage

msg = EmailMessage()
msg["From"] = "Billing Dept <billing@invoice-portal-secure.net>"
msg["To"] = "victim@example-corp.com"
msg["Subject"] = "Your Invoice #4471 is overdue - Immediate payment required"
msg["Date"] = "Fri, 11 Sep 2026 09:00:00 +0000"
msg["Authentication-Results"] = "mx.example-corp.com; spf=fail smtp.mailfrom=billing@invoice-portal-secure.net; dkim=none; dmarc=fail"
msg["Received"] = "from unknown (unknown [45.142.212.61]) by mx.example-corp.com; Fri, 11 Sep 2026 09:00:05 +0000"

msg.set_content(
    "Dear Sir/Madam,\n\n"
    "Your invoice #4471 is now overdue. Please find the attached invoice document "
    "and process payment immediately to avoid service suspension.\n\n"
    "Regards,\nBilling Department"
)

# Simulate a malicious attachment: a fake .exe disguised with a double extension
fake_exe_content = b"MZ\x90\x00" + b"FAKE_TEST_PAYLOAD_NOT_REAL_MALWARE" * 20
msg.add_attachment(
    fake_exe_content,
    maintype="application",
    subtype="octet-stream",
    filename="Invoice_4471.pdf.exe",
)

with open("samples/sample_with_attachment.eml", "wb") as f:
    f.write(msg.as_bytes())

print("Created samples/sample_with_attachment.eml")