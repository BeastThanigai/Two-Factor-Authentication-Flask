from flask import Flask, request, jsonify, session, render_template
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = 'a_secure_random_secret_key'

# In-memory store for demo purposes. In production, use a database.
user_data = {}

@app.route('/')
def home():
    return render_template("auth123.html")

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get("username")
    if username in user_data:
        return jsonify({"error": "User already exists"}), 400

    # Generate a unique secret key for TOTP
    secret = pyotp.random_base32()
    user_data[username] = {"secret": secret}
    session["username"] = username

    # Generate a QR code to scan with Google Authenticator or another TOTP app
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="YourApp")
    qr = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return jsonify({"qr_code": qr_code_base64, "secret": secret})

@app.route('/verify', methods=['POST'])
def verify():
    username = session.get("username")
    if not username or username not in user_data:
        return jsonify({"error": "User not found or not logged in"}), 400

    code = request.json.get("code")
    secret = user_data[username]["secret"]

    # Verify the code
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        return jsonify({"message": "2FA verification successful!"})
    else:
        return jsonify({"error": "Invalid code"}), 400

if __name__ == '__main__':
    app.run(debug=True)
