import os
import psycopg2
import psycopg2.extras # Important for getting dictionaries from the database
from flask import Flask, request, jsonify, render_template, redirect
from datetime import datetime, timedelta

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Configuration ---
# Get the database URL from the environment variables you set in Render
DATABASE_URL = os.getenv('DATABASE_URL')

# --- Database Connection Function ---
def get_db_connection():
    """Establishes a connection to the database."""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# --- Route for your client application to validate a key ---
@app.route('/validate_license', methods=['POST'])
def validate_license():
    data = request.json
    key = data.get('key')
    device_id = data.get('device_id')

    if not key or not device_id:
        return jsonify({"valid": False, "message": "Missing key or device ID"}), 400

    conn = get_db_connection()
    try:
        # Use a 'with' statement for the cursor, which handles closing automatically
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute("SELECT * FROM licenses WHERE key = %s", (key,))
            license_record = cursor.fetchone()

            if not license_record:
                return jsonify({'valid': False, 'message': 'License key does not exist.'}), 404

            if license_record['revoked']:
                return jsonify({'valid': False, 'message': 'This license key has been revoked.'}), 403

            # Check if the key is already assigned to a different device
            if license_record['used_on_device'] and license_record['used_on_device'] != device_id:
                return jsonify({'valid': False, 'message': 'License key is already in use on another device.'}), 403

            # Check if the license is expired
            expiration_date = license_record['creation_date'] + timedelta(days=license_record['valid_for_days'])
            if datetime.now(expiration_date.tzinfo) > expiration_date:
                return jsonify({'valid': False, 'message': 'This license key has expired.'}), 403

            # If the key is valid and not yet assigned, assign it to the current device
            if not license_record['used_on_device']:
                cursor.execute(
                    "UPDATE licenses SET used_on_device = %s WHERE key = %s",
                    (device_id, key)
                )
                conn.commit()
            
            return jsonify({'valid': True, 'message': 'License is valid.'})
    finally:
        # This 'finally' block ensures the connection is closed no matter what
        conn.close()

# --- Admin Panel Routes ---
@app.route('/admin') 
def admin_panel():
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute("SELECT * FROM licenses ORDER BY creation_date DESC")
            all_keys = cursor.fetchall()
        # Assumes you have an 'admin.html' in a 'templates' folder
        return render_template('admin.html', keys=all_keys)
    finally:
        conn.close()

@app.route('/add_key', methods=['POST'])
def add_key():
    new_key = request.form.get('key')
    validity_days = int(request.form.get('validity_days'))
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO licenses (key, valid_for_days) VALUES (%s, %s)",
                (new_key, validity_days)
            )
        conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Database error: {e}")
    finally:
        conn.close()
    
    return redirect('/admin') 

@app.route('/revoke_key', methods=['POST'])
def revoke_key():
    key_to_revoke = request.form.get('key')
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE licenses SET revoked = TRUE WHERE key = %s", (key_to_revoke,))
        conn.commit()
    finally:
        conn.close()

    return redirect('/admin')

# --- Server Start ---
if __name__ == "__main__":
    # Render provides the PORT environment variable.
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
