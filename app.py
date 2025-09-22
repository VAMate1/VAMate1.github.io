from flask import Flask, request, jsonify, render_template, Response
import json
import os
from datetime import datetime, timedelta
from functools import wraps
# --- NEW: Import libraries for .env loading and encryption ---
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# --- NEW: Load environment variables from .env file for local development ---
# This line should be at the top, before accessing any environment variables.
load_dotenv()

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE_PATH = os.path.join(BASE_DIR, "Keys.json")

# Get admin password from environment variable
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    print("⚠️ WARNING: ADMIN_PASSWORD environment variable not set. Admin panel is insecure.")

# --- NEW: Get encryption key from environment variable and initialize Fernet ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    # The application should not run without an encryption key.
    raise ValueError("❌ No ENCRYPTION_KEY set. Please set it in your environment variables or .env file.")

# This cipher_suite object can now be used for any server-side encryption needs.
cipher_suite = Fernet(ENCRYPTION_KEY.encode())
print("✅ Encryption key loaded successfully.")

# --- Authentication Decorator ---
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        # Check if ADMIN_PASSWORD is set before comparing
        if not ADMIN_PASSWORD or not auth or not (auth.username == 'admin' and auth.password == ADMIN_PASSWORD):
            return Response('Could not verify your access.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated

# --- License Key Management Functions ---
def load_keys():
    """Loads the license key data from the JSON file."""
    if not os.path.exists(KEYS_FILE_PATH):
        # If the file doesn't exist, create it with an empty object
        with open(KEYS_FILE_PATH, 'w') as f:
            json.dump({}, f)
        return {}
    
    with open(KEYS_FILE_PATH, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            print(f"❌ Error reading {KEYS_FILE_PATH}, returning empty data: {e}")
            return {}

def save_keys(keys_data):
    """Saves the updated license key data back to the JSON file."""
    with open(KEYS_FILE_PATH, 'w') as f:
        json.dump(keys_data, f, indent=4)

# --- Public API Route ---
@app.route('/validate_license', methods=['POST'])
def validate_license():
    data = request.get_json()
    if not data:
        return jsonify({"valid": False, "message": "Invalid request format"}), 400

    license_key = data.get('key')
    device_id = data.get('device_id')

    if not license_key or not device_id:
        return jsonify({"valid": False, "message": "Missing key or device ID"}), 400

    keys_database = load_keys()

    if license_key not in keys_database:
        print(f"❌ Key not found: {license_key}")
        return jsonify({"valid": False, "message": "Invalid key"}), 401

    key_info = keys_database[license_key]

    if key_info.get('revoked', False):
        print(f"❌ Key revoked: {license_key}")
        return jsonify({"valid": False, "message": "Key has been revoked"}), 403

    # Check for expiration if issuance_date is present
    if key_info.get('issuance_date'):
        try:
            issuance_date = datetime.strptime(key_info['issuance_date'], '%Y-%m-%d').date()
            valid_for_days = key_info.get('valid_for_days', 30)
            expiration_date = issuance_date + timedelta(days=valid_for_days)
            
            if datetime.now().date() > expiration_date:
                print(f"❌ License expired: {license_key}")
                return jsonify({"valid": False, "message": "License has expired."}), 403
        except (ValueError, TypeError):
             return jsonify({"valid": False, "message": "Invalid date format in key data."}), 500

    # Check device ID
    if key_info.get('used_on_device'):
        if key_info.get('used_on_device') != device_id:
            print(f"❌ Key {license_key} already in use by another device")
            return jsonify({"valid": False, "message": "Key is already in use on another device"}), 403
    else:
        # First time use: assign key to this device and set issuance date
        print(f"ℹ️ Assigning key {license_key} to device: {device_id}")
        keys_database[license_key]['used_on_device'] = device_id
        keys_database[license_key]['issuance_date'] = datetime.now().strftime('%Y-%m-%d')
        save_keys(keys_database)

    print(f"✅ License validated successfully for key: {license_key}")
    return jsonify({
        "valid": True,
        "message": "License validated successfully"
    }), 200

# --- Health Check Endpoint ---
@app.route('/health')
def health_check():
    return "OK", 200

# --- Admin Panel Routes ---
@app.route('/admin')
@requires_auth
def admin_panel():
    keys = load_keys()
    # Sort keys by creation date if available, otherwise alphabetically
    sorted_keys = sorted(keys.items(), key=lambda item: item[1].get('created_at', item[0]), reverse=True)
    return render_template('admin.html', keys=dict(sorted_keys))

@app.route('/add_key', methods=['POST'])
@requires_auth
def add_key():
    key = request.form.get('key')
    validity_days = request.form.get('validity_days', '30')
    
    if not key:
        return "Error: Key cannot be empty.", 400

    keys_data = load_keys()
    if key in keys_data:
        return "Error: Key already exists.", 409
    
    try:
        keys_data[key] = {
            "revoked": False,
            "used_on_device": None,
            "issuance_date": None,
            "valid_for_days": int(validity_days),
            "created_at": datetime.now().isoformat()
        }
        save_keys(keys_data)
        return "Key added successfully!", 200
    except ValueError:
        return "Error: Invalid input for validity days.", 400

@app.route('/revoke_key', methods=['POST'])
@requires_auth
def revoke_key():
    key = request.form.get('key')
    keys_data = load_keys()
    
    if key not in keys_data:
        return "Error: Key not found.", 404
        
    keys_data[key]['revoked'] = True
    save_keys(keys_data)
    return "Key revoked successfully!", 200

# --- Server Start ---
if __name__ == '__main__':
    print(f"🔑 Using keys file at: {KEYS_FILE_PATH}")
    # Use the PORT environment variable provided by Render, default to 5000 for local dev
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
