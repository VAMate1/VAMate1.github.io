import os
import psycopg2
import psycopg2.extras # Important for getting dictionaries from the database
from flask import Flask, request, jsonify, render_template, redirect
from datetime import datetime, timedelta
import secrets
import string
import random

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

# --- NEW: Health Check Endpoint ---
@app.route('/health')
def health_check():
    """A simple and fast endpoint for uptime monitoring."""
    return "OK", 200

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
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute("SELECT * FROM licenses WHERE key = %s", (key,))
            license_record = cursor.fetchone()

            if not license_record:
                return jsonify({'valid': False, 'message': 'License key does not exist.'}), 404

            if license_record['revoked']:
                return jsonify({'valid': False, 'message': 'This license key has been revoked.'}), 403

            if license_record['used_on_device'] and license_record['used_on_device'] != device_id:
                return jsonify({'valid': False, 'message': 'License key is already in use on another device.'}), 403

            expiration_date = license_record['creation_date'] + timedelta(days=license_record['valid_for_days'])
            if datetime.now(expiration_date.tzinfo) > expiration_date:
                return jsonify({'valid': False, 'message': 'This license key has expired.'}), 403

            if not license_record['used_on_device']:
                cursor.execute(
                    "UPDATE licenses SET used_on_device = %s WHERE key = %s",
                    (device_id, key)
                )
                conn.commit()
            
            return jsonify({'valid': True, 'message': 'License is valid.'})
    finally:
        conn.close()

# --- Admin Panel Routes ---
@app.route('/admin') 
def admin_panel():
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute("SELECT * FROM licenses ORDER BY creation_date DESC")
            all_keys = cursor.fetchall()
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

@app.route('/reinstate_key', methods=['POST'])
def reinstate_key():
    key_to_reinstate = request.form.get('key')
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE licenses SET revoked = FALSE WHERE key = %s", (key_to_reinstate,))
        conn.commit()
    finally:
        conn.close()
    return redirect('/admin')

@app.route('/modify_key', methods=['POST'])
def modify_key():
    key_to_modify = request.form.get('key')
    new_validity_days = int(request.form.get('validity_days'))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE licenses SET valid_for_days = %s WHERE key = %s",
                (new_validity_days, key_to_modify)
            )
        conn.commit()
    finally:
        conn.close()
    return redirect('/admin')

# --- Bulk Add and Key Generation Routes ---

@app.route('/mass_add_keys', methods=['POST'])
def mass_add_keys():
    keys_raw = request.form.get('keys_raw')
    validity_days = int(request.form.get('validity_days'))

    keys_to_add = [key.strip().upper() for key in keys_raw.splitlines() if key.strip()]
    if not keys_to_add:
        return redirect('/admin')

    values = [(key, validity_days) for key in keys_to_add]
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            psycopg2.extras.execute_values(
                cursor,
                "INSERT INTO licenses (key, valid_for_days) VALUES %s ON CONFLICT (key) DO NOTHING",
                values
            )
        conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Database error during bulk insert: {e}")
    finally:
        conn.close()
    
    return redirect('/admin')

def generate_key(cursor, parts=3, part_length=4):
    """
    Generates a cryptographically secure, unique key in an XXXX-XXXX-XXXX format
    and ensures it does not already exist in the database.
    """
    alphabet = string.ascii_uppercase + string.digits
    while True:
        key_parts = []
        for _ in range(parts):
            part = ''.join(secrets.choice(alphabet) for _ in range(part_length))
            key_parts.append(part)
        
        new_key = '-'.join(key_parts)
        
        cursor.execute("SELECT 1 FROM licenses WHERE key = %s", (new_key,))
        if cursor.fetchone() is None:
            return new_key

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    try:
        quantity = int(request.form.get('quantity'))
        validity_days = int(request.form.get('validity_days'))
    except (ValueError, TypeError):
        return "Invalid input", 400

    keys_to_add = set()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            for _ in range(quantity):
                unique_key = generate_key(cursor)
                keys_to_add.add(unique_key)

        if not keys_to_add:
            return redirect('/admin')

        values = [(key, validity_days) for key in keys_to_add]

        with conn.cursor() as cursor:
            psycopg2.extras.execute_values(
                cursor,
                "INSERT INTO licenses (key, valid_for_days) VALUES %s",
                values
            )
        conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Database error during key generation: {e}")
    finally:
        conn.close()

    return redirect('/admin')

# --- Server Start ---
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
