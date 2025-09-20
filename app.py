from flask import Flask, request, jsonify, render_template, Response
import json
import os
from datetime import datetime, timedelta
from functools import wraps

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE_PATH = os.path.join(BASE_DIR, "Keys.json")

# Get admin password from environment variable
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# --- Authentication Decorator ---
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == 'admin' and auth.password == ADMIN_PASSWORD):
            return Response('Could not verify your access.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated

# --- License Key Management Functions ---
def load_keys():
    """Loads the license key data from the JSON file."""
    if os.path.exists(KEYS_FILE_PATH):
        with open(KEYS_FILE_PATH, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                print(f"❌ Error reading {KEYS_FILE_PATH}: {e}")
                return {}
    # If the file doesn't exist, return an empty dictionary and create a new file
    with open(KEYS_FILE_PATH, 'w') as f:
        json.dump({}, f)
    return {}

def save_keys(keys_data):
    """Saves the updated license key data back to the JSON file."""
    with open(KEYS_FILE_PATH, 'w') as f:
        json.dump(keys_data, f, indent=4)

# --- Public API Route ---
@app.route('/validate_license', methods=['POST'])
def validate_license():
    data = request.get_json()
    license_key = data.get('key')
    device_id = data.get('device_id')

    print("\n>>> Incoming request")
    print("License requested:", repr(license_key))
    print("Device ID:", repr(device_id))

    keys_database = load_keys()
    print("Loaded keys from file:", list(keys_database.keys()))
    print("Looking for key:", repr(license_key))

    if not license_key or not device_id:
        return jsonify({"valid": False, "message": "Missing key or device ID"}), 400

    if license_key not in keys_database:
        print("❌ Key not found in Keys.json")
        return jsonify({"valid": False, "message": "Invalid key"}), 401

    key_info = keys_database[license_key]

    if key_info.get('revoked', False):
        print("❌ Key revoked")
        return jsonify({"valid": False, "message": "Key has been revoked"}), 403

    if key_info.get('issuance_date'):
        issuance_date = datetime.strptime(key_info['issuance_date'], '%Y-%m-%d').date()
        valid_for_days = key_info.get('valid_for_days', 30)
        expiration_date = issuance_date + timedelta(days=valid_for_days)
        
        if datetime.now().date() > expiration_date:
            print("❌ License expired")
            return jsonify({"valid": False, "message": "License has expired."}), 403

    if key_info.get('used_on_device'):
        if key_info.get('used_on_device') != device_id:
            print("❌ Key already in use by another device")
            return jsonify({"valid": False, "message": "Key is already in use on another device"}), 403
    else:
        print("ℹ️ Assigning key to this device:", device_id)
        keys_database[license_key]['used_on_device'] = device_id
        keys_database[license_key]['issuance_date'] = datetime.now().strftime('%Y-%m-%d')
        save_keys(keys_database)

    print("✅ License validated successfully")

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
    return render_template('admin.html', keys=keys)

@app.route('/add_key', methods=['POST'])
@requires_auth
def add_key():
    key = request.form.get('key')
    validity_days = request.form.get('validity_days', 30)
    
    keys_data = load_keys()
    if key in keys_data:
        return "Error: Key already exists.", 409
    
    try:
        keys_data[key] = {
            "revoked": False,
            "valid_for_days": int(validity_days),
            "created_at": datetime.now().isoformat()
        }
        save_keys(keys_data)
        return "Key added successfully!", 200
    except ValueError:
        return "Error: Invalid validity days.", 400

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
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000))
