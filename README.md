# SSL_monitor
🔒 SSL Certificate Monitor


A simple Python utility to **monitor SSL/TLS certificate expiration** for any domain — with optional **email** and **Telegram alerts**.

This script is perfect for DevOps, sysadmins, and developers who need to ensure that certificates don’t expire unexpectedly.

---

## 🧩 Features

✅ Check SSL/TLS certificate validity for any host  
✅ Warn when expiration is near (default: 30 days)  
✅ Output structured and human-readable info  
✅ Send alerts via:
- 📧 Email (SMTP)
- 💬 Telegram bot  
✅ Easy integration with cron, systemd, or CI/CD pipelines  
✅ Clean exit codes for monitoring systems (0=OK, 1=Warning, 2=Error)

## ⚙️ Installation

Clone the repository and install dependencies:

```
git clone https://github.com/ryu878/SSL_monitor.git
cd SSL_monitor
conda create --name SSL_monitor -c conda-forge python=3.11
conda activate SSL_monitor
pip install -r requirements.txt
```

Or install manually:

```
pip install cryptography requests
```

🚀 Usage

Run a simple check for the default domain (aadresearch.xyz):

```
python3 ssl_monitor.py
```

Example output:
```
Host: aadresearch.xyz:443
Subject: CN=aadresearch.xyz
Issuer: CN=R3,O=Let's Encrypt,C=US
Not Before: 2025-08-01T12:00:00+00:00
Not After:  2025-10-30T12:00:00+00:00
DAYS UNTIL EXPIRY: 23
SANs: aadresearch.xyz, www.aadresearch.xyz
```

⚡ Examples
Check a custom host

```
python3 ssl_monitor.py --host example.com --port 443
```

Change warning threshold
```
python3 ssl_monitor.py --warn-days 14
```

📧 Email Alerts

To enable email notifications when a certificate is near expiration:

```
python3 ssl_monitor.py \
  --email-from you@example.com \
  --email-to admin@example.com \
  --smtp-server smtp.example.com \
  --smtp-port 587 \
  --smtp-user you@example.com \
  --smtp-pass "password"
```

The script will automatically send an alert email if the certificate expires within the --warn-days period.

💬 Telegram Alerts

Set up a Telegram bot and get instant alerts.

Create a bot via @BotFather

Get your bot token and chat ID

Run:

```
python3 ssl_monitor.py \
  --telegram-bot-token 123456:ABCDEF123456 \
  --telegram-chat-id 987654321
```

You’ll receive alerts like:

```
⚠️ CERT ALERT for aadresearch.xyz
Days left: 23
Subject: CN=aadresearch.xyz
Issuer: Let's Encrypt R3
```

🕒 Cron Job Setup

Run daily at 08:00 and log output to /var/log/ssl_monitor.log:

```
0 8 * * * /usr/bin/python3 /opt/ssl_monitor/ssl_monitor.py \
  --email-from ops@example.com \
  --email-to ops@example.com \
  --smtp-server smtp.example.com \
  --smtp-user ops@example.com \
  --smtp-pass 'password' \
  >> /var/log/ssl_monitor.log 2>&1
```

🧠 Systemd Timer (optional)

If you prefer systemd:

Create /etc/systemd/system/ssl-monitor.service:

```
[Unit]
Description=SSL Certificate Monitor

[Service]
ExecStart=/usr/bin/python3 /opt/ssl_monitor/ssl_monitor.py
```

Then /etc/systemd/system/ssl-monitor.timer:

```
[Unit]
Description=Run SSL monitor daily

[Timer]
OnCalendar=*-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:

```
sudo systemctl enable ssl-monitor.timer
sudo systemctl start ssl-monitor.timer
```

🧰 Example Automation Integration
Nagios / Zabbix / Prometheus

Use exit codes (0/1/2) to create simple monitoring checks.

Example:

```
python3 ssl_monitor.py --host aadresearch.xyz --warn-days 15
```

If it exits with code 1, trigger your alert rule.

## Contacts
I develop trading bots of any complexity, dashboards and indicators for crypto exchanges, forex and stocks.
To contact me please pm:

Telegram: https://t.me/ryu8777

Discord: https://discord.gg/zSw58e9Uvf
