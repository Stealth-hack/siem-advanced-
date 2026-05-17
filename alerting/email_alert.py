import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "uabdulrahman4188@gmail.com"
SENDER_PASSWORD = "zwpg ukdp yhfl nsxm"
RECEIVER_EMAIL = "uabdulrahman4188@gmail.com"

def send_alert_email(alert):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = f"🚨 SIEM ALERT: {alert['alert']}"

        body = f"""
SIEM SECURITY ALERT
===================
Type:       {alert['alert']}
IP Address: {alert['ip']}
Attempts:   {alert['attempts']}
Timestamp:  {alert['timestamp']}
Detected:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This is an automated alert from your SIEM system.
        """

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()

        print(f"[+] Alert email sent to {RECEIVER_EMAIL}")
        return True

    except Exception as e:
        print(f"[!] Failed to send email: {e}")
        return False
