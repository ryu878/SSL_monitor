#!/usr/bin/env python3
"""
ssl_monitor.py

Monitor an SSL/TLS certificate for a host and optionally send alerts via email or Telegram.

Usage examples:
  # Basic check for aadresearch.xyz with default 30-day warning:
  python3 ssl_monitor.py

  # Check a different host and port:
  python3 ssl_monitor.py --host example.com --port 443

  # Email alert if expiring:
  python3 ssl_monitor.py --email-from you@example.com --email-to ops@example.com \
      --smtp-server smtp.example.com --smtp-port 587 --smtp-user you --smtp-pass secret

  # Telegram alert:
  python3 ssl_monitor.py --telegram-bot-token 123:ABC --telegram-chat-id 987654321

Exit codes:
  0 - certificate OK (not within warning days)
  1 - certificate is expiring soon (<= warning days)
  2 - error occurred while checking
"""

import argparse
import socket
import ssl
import sys
import smtplib
import json
from datetime import datetime, timezone
from email.message import EmailMessage

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    print("ERROR: This script requires the 'cryptography' package. Install with: pip install cryptography")
    raise

try:
    import requests
except Exception:
    requests = None  # Telegram alerts will require 'requests'


def fetch_certificate_pem(host: str, port: int = 443, timeout: float = 5.0) -> str:
    """Fetch the server certificate in PEM format using ssl.get_server_certificate."""
    try:
        pem = ssl.get_server_certificate((host, port), timeout=timeout)
        return pem
    except Exception as e:
        raise RuntimeError(f"Failed to get certificate from {host}:{port} — {e}")


def parse_certificate(pem_data: str):
    """Parse PEM certificate and return x509 object and useful fields."""
    cert = x509.load_pem_x509_certificate(pem_data.encode("utf-8"), default_backend())
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    # Use timezone-aware datetime properties (no deprecation warning)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    # subject alternative names (SANs)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []

    return {
        "cert": cert,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "sans": sans,
    }


def days_until(dt: datetime) -> int:
    """Return number of whole days from now (UTC) until dt. Negative if expired."""
    now = datetime.now(timezone.utc)
    delta = dt - now
    return int(delta.total_seconds() // 86400)


def send_email(smtp_server, smtp_port, smtp_user, smtp_pass, sender, recipients, subject, body, use_tls=True):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients if isinstance(recipients, list) else [recipients])
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as s:
            if use_tls:
                s.starttls()
            if smtp_user:
                s.login(smtp_user, smtp_pass)
            s.send_message(msg)
    except Exception as e:
        raise RuntimeError(f"Failed to send email: {e}")


def send_telegram(bot_token: str, chat_id: str, text: str):
    if requests is None:
        raise RuntimeError("To send Telegram messages install the requests package: pip install requests")
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    r = requests.post(url, data=payload, timeout=10)
    if not r.ok:
        raise RuntimeError(f"Telegram API returned {r.status_code}: {r.text}")
    return r.json()


def build_report(host, port, info, days_left) -> str:
    lines = []
    lines.append(f"Host: {host}:{port}")
    lines.append(f"Subject: {info['subject']}")
    lines.append(f"Issuer: {info['issuer']}")
    lines.append(f"Not Before: {info['not_before'].isoformat()}")
    lines.append(f"Not After:  {info['not_after'].isoformat()}")
    lines.append(f"DAYS UNTIL EXPIRY: {days_left}")
    if info["sans"]:
        lines.append("SANs: " + ", ".join(info["sans"]))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="SSL certificate monitor")
    parser.add_argument("--host", default="aadresearch.xyz", help="Hostname to check (default: aadresearch.xyz)")
    parser.add_argument("--port", default=443, type=int, help="TLS port (default: 443)")
    parser.add_argument("--timeout", default=5.0, type=float, help="Socket timeout in seconds")
    parser.add_argument("--warn-days", default=30, type=int, help="Warn if cert expires within WARN_DAYS (default 30)")
    # Email options
    parser.add_argument("--email-from", help="Send alert email from this address")
    parser.add_argument("--email-to", nargs="+", help="Send alert email to these addresses (space-separated)")
    parser.add_argument("--smtp-server", help="SMTP server")
    parser.add_argument("--smtp-port", type=int, default=587, help="SMTP port")
    parser.add_argument("--smtp-user", help="SMTP username (optional)")
    parser.add_argument("--smtp-pass", help="SMTP password (optional)")
    # Telegram options
    parser.add_argument("--telegram-bot-token", help="Telegram bot token (for alerts)")
    parser.add_argument("--telegram-chat-id", help="Telegram chat id to send alerts to")
    args = parser.parse_args()

    host = args.host
    port = args.port

    try:
        pem = fetch_certificate_pem(host, port, timeout=args.timeout)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(2)

    try:
        info = parse_certificate(pem)
    except Exception as e:
        print(f"[ERROR] Failed to parse certificate: {e}", file=sys.stderr)
        sys.exit(2)

    days_left = days_until(info["not_after"])
    report = build_report(host, port, info, days_left)
    print(report)

    is_warning = days_left <= args.warn_days

    # If expiring or within warning, send alerts if configured
    if is_warning:
        subject = f"[ALERT] Certificate for {host} expires in {days_left} day(s)"
        body = report
        # Email alert
        if args.email_from and args.email_to and args.smtp_server:
            try:
                send_email(
                    smtp_server=args.smtp_server,
                    smtp_port=args.smtp_port,
                    smtp_user=args.smtp_user,
                    smtp_pass=args.smtp_pass,
                    sender=args.email_from,
                    recipients=args.email_to,
                    subject=subject,
                    body=body,
                    use_tls=True,
                )
                print("[INFO] Email alert sent.")
            except Exception as e:
                print(f"[ERROR] Email send failed: {e}", file=sys.stderr)
        # Telegram alert
        if args.telegram_bot_token and args.telegram_chat_id:
            try:
                tg_text = f"*CERT ALERT* for `{host}`\nDays left: *{days_left}*\n\nSubject: `{info['subject']}`\nIssuer: `{info['issuer']}`"
                send_telegram(args.telegram_bot_token, args.telegram_chat_id, tg_text)
                print("[INFO] Telegram alert sent.")
            except Exception as e:
                print(f"[ERROR] Telegram send failed: {e}", file=sys.stderr)

    # Return appropriate exit code
    if is_warning:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()