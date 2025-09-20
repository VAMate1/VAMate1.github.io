from flask import Flask, request, jsonify
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# Always resolve Keys.json relative to this script's folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE_PATH = os.path.join(BASE_DIR, "Keys.json")

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

    # Check for expiration if the key has an issuance date
    if key_info.get('issuance_date'):
        issuance_date = datetime.strptime(key_info['issuance_date'], '%Y-%m-%d').date()
        valid_for_days = key_info.get('valid_for_days', 30) # Default to 30 days
        expiration_date = issuance_date + timedelta(days=valid_for_days)
        
        # 💡 Use the server's current date for validation
        if datetime.now().date() > expiration_date:
            print("❌ License expired")
            return jsonify({"valid": False, "message": "License has expired."}), 403

    # Check if the key is already in use
    if key_info.get('used_on_device'):
        if key_info.get('used_on_device') != device_id:
            print("❌ Key already in use by another device")
            return jsonify({"valid": False, "message": "Key is already in use on another device"}), 403
    else:
        # If the key is not yet assigned, assign it and add the issuance date
        print("ℹ️ Assigning key to this device:", device_id)
        keys_database[license_key]['used_on_device'] = device_id
        # 💡 Add the issuance date when the key is first used
        keys_database[license_key]['issuance_date'] = datetime.now().strftime('%Y-%m-%d')
        save_keys(keys_database)

    print("✅ License validated successfully")

    return jsonify({
        "valid": True,
        "message": "License validated successfully"
    }), 200

if __name__ == '__main__':
    print(f"🔑 Using keys file at: {KEYS_FILE_PATH}")
    app.run(host='0.0.0.0', port=5000)