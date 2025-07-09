from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import pyotp
import qrcode
import base64
from io import BytesIO
import os
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)

# === Google Sheets Setup ===
scope = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

# --- Google Credentials from ENV ---
creds_json = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON")
if not creds_json:
    raise Exception("Missing GOOGLE_APPLICATION_CREDENTIALS_JSON environment variable")

creds_dict = json.loads(creds_json)
creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, scope)

client = gspread.authorize(creds)
sheet = client.open_by_key("1hyoQZpD17tsTjSh1XqgAUvfZ4Nt3kwV7zxphosruXeE").worksheet("Sheet1")

# === Routes ===
@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    all_data = sheet.get_all_values()
    headers = all_data[1]
    email_col = headers.index("EmailAddress") + 1
    password_col = headers.index("Password") + 1
    secret_col = headers.index("SecretKey") + 1
    blocked_col = headers.index("Blocked") + 1

    for i, row in enumerate(all_data[2:], start=3):
        try:
            if row[email_col - 1] == email:
                if row[password_col - 1] != password:
                    return jsonify({"success": False, "message": "Incorrect password"})
                if row[blocked_col - 1].strip().lower() in ["blocked", "yes"]:
                    return jsonify({"success": False, "message": "Your account is blocked."})

                session["email"] = email

                secret = row[secret_col - 1].strip()
                if not secret:
                    new_secret = pyotp.random_base32()
                    sheet.update_cell(i, secret_col, new_secret)
                return jsonify({"success": True})
        except IndexError:
            continue

    return jsonify({"success": False, "message": "Email not found"})

@app.route("/otp")
def otp():
    if "email" not in session:
        return redirect(url_for("index"))

    email = session["email"]
    all_data = sheet.get_all_values()
    headers = all_data[1]
    email_col = headers.index("EmailAddress") + 1
    secret_col = headers.index("SecretKey") + 1

    for i, row in enumerate(all_data[2:], start=3):
        try:
            if row[email_col - 1] == email:
                secret = row[secret_col - 1].strip()
                if not secret:
                    return "SecretKey not found for this user."

                totp = pyotp.TOTP(secret)
                uri = totp.provisioning_uri(name=email, issuer_name="ELPL Employee Portal")

                qr_img = qrcode.make(uri)
                buffered = BytesIO()
                qr_img.save(buffered, format="PNG")
                qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

                return render_template("otp.html", email=email, qr_base64=qr_base64)
        except IndexError:
            continue

    return "User not found", 404

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    if "email" not in session:
        return redirect(url_for("index"))

    otp_entered = request.form.get("otp")
    email = session["email"]

    all_data = sheet.get_all_values()
    headers = all_data[1]
    email_col = headers.index("EmailAddress") + 1
    secret_col = headers.index("SecretKey") + 1

    for i, row in enumerate(all_data[2:], start=3):
        if row[email_col - 1] == email:
            secret = row[secret_col - 1].strip()
            if pyotp.TOTP(secret).verify(otp_entered):
                return render_template("success.html", email=email)
            else:
                return "❌ Invalid OTP. Please try again."

    return "User not found", 404
