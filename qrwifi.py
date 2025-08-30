from flask import Flask, render_template_string, render_template, request, jsonify, redirect, url_for, session
import qrcode
import json
import os
from datetime import datetime
import base64
from io import BytesIO
import secrets
import secrets
import string
from functools import wraps
from flask_wtf import CSRFProtect




app = Flask(__name__)

# Path to config file
API_CONFIG_FILE = "api.json"

# File to store QR code library
LIBRARY_FILE = 'qr_library.json'

app.secret_key = secrets.token_hex(16)  # Needed for session
csrf = CSRFProtect(app)

def load_or_create_api_key():
    """Load API key from config file, or generate and save one if not found"""
    if os.path.exists(API_CONFIG_FILE):
        with open(API_CONFIG_FILE, "r") as f:
            config = json.load(f)
            if "API_KEY" in config:
                return config["API_KEY"]

    # If no config file or missing key, generate one
    api_key = "qr_api_" + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    with open(API_CONFIG_FILE, "w") as f:
        json.dump({"API_KEY": api_key}, f, indent=4)
    return api_key

# Load or create key
API_KEY = load_or_create_api_key()

def require_api_key(f):
    """Decorator to require API key from headers or query string"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check header
        api_key = request.headers.get('X-API-Key')
        
        # If not found, try query string
        if not api_key:
            api_key = request.args.get('api_key')
        
        # Special case: admin_internal_access
        if api_key == 'admin_internal_access':
            auth = request.authorization
            if not auth or auth.username != 'admin' or auth.password != 'qr12345':
                return jsonify({'error': 'Invalid admin credentials'}), 401
        
        elif api_key != API_KEY:
            return jsonify({'error': 'Invalid or missing API key'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def load_library():
    """Load the QR code library from file"""
    if os.path.exists(LIBRARY_FILE):
        with open(LIBRARY_FILE, 'r') as f:
            return json.load(f)
    return []

def save_library(library):
    """Save the QR code library to file"""
    with open(LIBRARY_FILE, 'w') as f:
        json.dump(library, f, indent=2)

def generate_wifi_string(ssid, password, security='WPA', hidden=False):
    """Generate WiFi QR code string format"""
    # Map security types to proper QR code format
    security_mapping = {
        'WPA': 'WPA',
        'WPA2': 'WPA', 
        'WPA3': 'SAE',  # WPA3 uses SAE (Simultaneous Authentication of Equals)
        'WEP': 'WEP',
        'nopass': ''
    }
    
    security_type = security_mapping.get(security.upper(), security.upper())
    hidden_flag = 'true' if hidden else 'false'
    
    # WiFi QR code format: WIFI:T:WPA;S:mynetwork;P:mypass;H:false;;
    wifi_string = f"WIFI:T:{security_type};S:{ssid};P:{password};H:{hidden_flag};;"
    return wifi_string

def generate_random_id(length=12):
    """Generate random alphanumeric ID"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def create_qr_code(data):
    """Create QR code and return as base64 string"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for web display
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return img_str

@app.route('/')
def root():
    """Root endpoint - placeholder for your existing HTML"""
    return '''
    <html>
        <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
            <h1>Welcome</h1>
            <p>This is the root endpoint for your existing application.</p>
            <p><a href="/admin">WiFi QR Generator Admin</a></p>
        </body>
    </html>
    '''

@app.route('/admin/regenerate-key', methods=['POST'])
def regenerate_api_key():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_page'))

    new_key = "qr_api_" + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    config = {"API_KEY": new_key}
    with open(API_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

    global API_KEY
    API_KEY = new_key

    return redirect(url_for('show_api_key'))



@app.route('/admin')
def admin_page():
    """Password-protected admin page"""
    auth = request.authorization
    if not auth or auth.username != 'admin' or auth.password != 'qr123':
        return '''You must authenticate to access this page''', 401, {
            'WWW-Authenticate': 'Basic realm="WiFi QR Admin"'
        }

    # Mark user as logged in
    session['admin_logged_in'] = True

    library = load_library()
    return render_template("admin.html", library=library)
  
@app.route('/logout')
def logout():
    """Logout endpoint that redirects back to admin"""
    return '''
    <script>
        // Clear authentication and redirect
        window.location.replace("/admin");
    </script>
    <p>Logging out... <a href="/admin">Click here if not redirected</a></p>
    ''', 401, {
        'WWW-Authenticate': 'Basic realm="WiFi QR Admin"'
    }

@app.route('/wifi', methods=['POST'])
def generate_wifi_qr():
    """Generate WiFi QR code"""
    try:
        data = request.get_json()
        
        ssid = data.get('ssid', '')
        password = data.get('password', '')
        security = data.get('security', 'WPA')
        hidden = data.get('hidden', False)
        
        if not ssid:
            return jsonify({'error': 'SSID is required'}), 400
        
        # Generate WiFi string
        wifi_string = generate_wifi_string(ssid, password, security, hidden)
        
        # Create QR code
        qr_image = create_qr_code(wifi_string)
        
        # Load library and add new entry
        library = load_library()
        
        # Generate random IDs for URLs
        qr_id = generate_random_id()
        embed_id = generate_random_id()
        update_id = generate_random_id()  # For password updates
        
        new_entry = {
            'id': len(library) + 1,
            'qr_id': qr_id,
            'embed_id': embed_id,
            'update_id': update_id,
            'ssid': ssid,
            'password': password,
            'security': security,
            'hidden': hidden,
            'created_at': datetime.now().isoformat(),
            'wifi_string': wifi_string,
            'qr_image': qr_image
        }
        
        library.append(new_entry)
        save_library(library)
        
        return jsonify({
            'success': True,
            'qr_image': qr_image,
            'wifi_string': wifi_string,
            'entry': new_entry
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/wifi/<qr_id>', methods=['PUT'])
def update_wifi_qr(qr_id):
    """Update existing WiFi QR code using qr_id"""
    try:
        data = request.get_json()
        library = load_library()
        
        # Find the entry to update using qr_id
        entry_index = None
        for i, entry in enumerate(library):
            if entry.get('qr_id') == qr_id:
                entry_index = i
                break
        
        if entry_index is None:
            return jsonify({'error': 'Entry not found'}), 404
        
        # Update entry data
        ssid = data.get('ssid', library[entry_index]['ssid'])
        password = data.get('password', library[entry_index]['password'])
        security = data.get('security', library[entry_index]['security'])
        hidden = data.get('hidden', library[entry_index]['hidden'])
        
        if not ssid:
            return jsonify({'error': 'SSID is required'}), 400
        
        # Generate new WiFi string and QR code
        wifi_string = generate_wifi_string(ssid, password, security, hidden)
        qr_image = create_qr_code(wifi_string)
        
        # Update the entry
        library[entry_index].update({
            'ssid': ssid,
            'password': password,
            'security': security,
            'hidden': hidden,
            'updated_at': datetime.now().isoformat(),
            'wifi_string': wifi_string,
            'qr_image': qr_image
        })
        
        # Generate new random IDs if they don't exist
        if 'qr_id' not in library[entry_index]:
            library[entry_index]['qr_id'] = generate_random_id()
        if 'embed_id' not in library[entry_index]:
            library[entry_index]['embed_id'] = generate_random_id()
        if 'update_id' not in library[entry_index]:
            library[entry_index]['update_id'] = generate_random_id()
        
        save_library(library)
        
        return jsonify({
            'success': True,
            'entry': library[entry_index]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/update-password/<update_id>', methods=['POST'])
@require_api_key 
def update_password_only(update_id):
    """API to update only the WiFi password using update_id"""
    try:
        data = request.get_json()
        new_password = data.get('password', '')
        
        library = load_library()
        
        # Find the entry to update using update_id
        entry_index = None
        for i, entry in enumerate(library):
            if entry.get('update_id') == update_id:
                entry_index = i
                break
        
        if entry_index is None:
            return jsonify({'error': 'Update ID not found'}), 404
        
        # Update only the password and regenerate QR code
        library[entry_index]['password'] = new_password
        library[entry_index]['updated_at'] = datetime.now().isoformat()
        
        # Regenerate WiFi string and QR code
        wifi_string = generate_wifi_string(
            library[entry_index]['ssid'],
            new_password,
            library[entry_index]['security'],
            library[entry_index]['hidden']
        )
        qr_image = create_qr_code(wifi_string)
        
        library[entry_index]['wifi_string'] = wifi_string
        library[entry_index]['qr_image'] = qr_image
        
        save_library(library)
        
        return jsonify({
            'success': True,
            'message': 'Password updated successfully',
            #'entry': library[entry_index]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
csrf.exempt(update_password_only)

@app.route('/library')
@require_api_key
def get_library():
    """Get all QR codes from library (API key required)"""
    library = load_library()
    # Remove sensitive data for API response
    safe_library = []
    for item in library:
        safe_item = {
            'qr_id': item.get('qr_id'),
            'embed_id': item.get('embed_id'),
            'ssid': item.get('ssid'),
            'security': item.get('security'),
            'hidden': item.get('hidden'),
            'created_at': item.get('created_at'),
            'updated_at': item.get('updated_at')
        }
        safe_library.append(safe_item)
    return jsonify(safe_library)
csrf.exempt(get_library)

@app.route('/library/<qr_id>', methods=['GET'])
@require_api_key
def get_library_entry(qr_id):
    library = load_library()
    entry = next((item for item in library if item.get('qr_id') == qr_id), None)
    if entry:
        return jsonify(entry)
    return jsonify({'error': 'Entry not found'}), 404
csrf.exempt(get_library_entry)

@app.route('/library/<qr_id>', methods=['DELETE'])
@require_api_key
def delete_library_entry(qr_id):
    """Delete QR code from library"""
    library = load_library()
    library = [item for item in library if item.get('qr_id') != qr_id]
    save_library(library)
    return jsonify({'success': True})
csrf.exempt(delete_library_entry)

@app.route('/qr/<qr_id>')
def get_qr_fullscreen(qr_id):
    """Get QR code in fullscreen for embedding"""
    library = load_library()
    entry = next((item for item in library if item.get('qr_id') == qr_id), None)
    
    if not entry:
        return jsonify({'error': 'QR code not found'}), 404
   
    
    #return render_template_string(fullscreen_template, entry=entry)
    return render_template("qr_fullscreen.html", entry=entry)
    
@app.route('/embed/<embed_id>')
def get_qr_embed(embed_id):
    """Get QR code for embedding in websites (minimal design)"""
    library = load_library()
    entry = next((item for item in library if item.get('embed_id') == embed_id), None)
    
    if not entry:
        return jsonify({'error': 'QR code not found'}), 404
 
    
    #return render_template_string(embed_template, entry=entry)
    return render_template("embed_template.html", entry=entry)

@app.route('/webhook/<qr_id>')
def webhook_update(qr_id):
    """Webhook endpoint to check for updates"""
    library = load_library()
    entry = next((item for item in library if item.get('qr_id') == qr_id or item.get('embed_id') == qr_id), None)
    
    if not entry:
        return jsonify({'error': 'Entry not found'}), 404
    
    # Return the latest data
    return jsonify({
        'id': entry['id'],
        'ssid': entry['ssid'],
        'security': entry['security'],
        'hidden': entry['hidden'],
        'qr_image': entry['qr_image'],
        'updated_at': entry.get('updated_at', entry.get('created_at')),
        'last_modified': os.path.getmtime(LIBRARY_FILE) if os.path.exists(LIBRARY_FILE) else 0
    })
    

@app.route('/admin/api-key')
def show_api_key():
    """Show API key for admin (password protected)"""
    auth = request.authorization
    if not auth or auth.username != 'admin' or auth.password != 'qr123':
        return '''You must authenticate to access this page''', 401, {
            'WWW-Authenticate': 'Basic realm="WiFi QR Admin"'
        }
    
    server_ip = request.host.split(":")[0]  # current host without port
    return render_template("api_key.html", api_key=API_KEY, server_ip=server_ip)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=80)