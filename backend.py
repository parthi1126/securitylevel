from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import pyotp
import qrcode
import base64
from io import BytesIO  # ✅ This line is required
import os


app = Flask(__name__)
app.secret_key = os.urandom(24)

# === Google Sheets Setup ===
scope = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]
creds = ServiceAccountCredentials.from_json_keyfile_name("service_account.json", scope)
client = gspread.authorize(creds)
sheet = client.open_by_key("1hyoQZpD17tsTjSh1XqgAUvfZ4Nt3kwV7zxphosruXeE").worksheet("Sheet1")

# === Route: Home/Login Page ===
@app.route("/")
def index():
    return render_template("login.html")

# === Route: Login Auth Check ===
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    all_data = sheet.get_all_values()
    headers = all_data[1]  # Assuming headers are on 2nd row
    email_col = headers.index("EmailAddress") + 1
    password_col = headers.index("Password") + 1
    secret_col = headers.index("SecretKey") + 1
    blocked_col = headers.index("Blocked") + 1

    for i, row in enumerate(all_data[2:], start=3):  # Skip first 2 header rows
        try:
            if row[email_col - 1] == email:
                if row[password_col - 1] != password:
                    return jsonify({"success": False, "message": "Incorrect password"})
                if row[blocked_col - 1].strip().lower() in ["blocked", "yes"]:
                    return jsonify({"success": False, "message": "Your account is blocked."})

                session["email"] = email

                # Check and assign secret key
                secret = row[secret_col - 1].strip()
                if not secret:
                    new_secret = pyotp.random_base32()
                    sheet.update_cell(i, secret_col, new_secret)
                return jsonify({"success": True})
        except IndexError:
            continue

    return jsonify({"success": False, "message": "Email not found"})

# === Route: Show OTP Page ===
import base64

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

                # Generate QR code as base64
                qr_img = qrcode.make(uri)
                buffered = BytesIO()
                qr_img.save(buffered, format="PNG")
                qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

                return render_template("otp.html", email=email, qr_base64=qr_base64)
        except IndexError:
            continue

    return "User not found", 404




# === Route: Verify OTP ===
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
                return "✅ Login Successful: Two-step verification completed!"
            else:
                return "❌ Invalid OTP. Please try again."

    return "User not found", 404


# === Start the Server ===
if __name__ == "__main__":
    app.run(debug=True)

