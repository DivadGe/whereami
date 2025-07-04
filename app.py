import sqlite3
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
import os
import time
import jwt
from datetime import datetime, timedelta
import json
import threading # For locking JSON file operations

app = Flask(__name__)
app.config['DATABASE'] = 'location_sharing.db'
app.config['SECRET_KEY'] = os.urandom(24) # Used for session management, but JWT will handle auth
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-jwt-key-please-change-in-production') # IMPORTANT: Use a strong, unique key in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30) # Token valid for 30 days

# --- JSON Config File Setup ---
CONFIG_FILE_PATH = 'user_group_config.json'
config_lock = threading.Lock() # To prevent race conditions when writing to JSON

def load_config():
    """Loads the user and group configuration from the JSON file."""
    with config_lock:
        if not os.path.exists(CONFIG_FILE_PATH):
            # Create an empty config file if it doesn't exist
            initial_config = {"users": [], "groups": []}
            with open(CONFIG_FILE_PATH, 'w') as f:
                json.dump(initial_config, f, indent=4)
            return initial_config
        
        with open(CONFIG_FILE_PATH, 'r') as f:
            return json.load(f)

def save_config(config_data):
    """Saves the user and group configuration to the JSON file."""
    with config_lock:
        with open(CONFIG_FILE_PATH, 'w') as f:
            json.dump(config_data, f, indent=4)

# --- Database Setup ---
# Flag to ensure database initialization runs only once per application instance
_db_initialized = threading.Event()

def init_db():
    """
    Initializes the database schema (only users and locations tables).
    Ensures it runs only once per application lifecycle.
    """
    if _db_initialized.is_set():
        return # Already initialized

    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        # Create locations table (time-series)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                timestamp INTEGER NOT NULL, -- Unix timestamp
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()
    print("Database initialized.")
    # Ensure config file exists on startup
    load_config()
    print(f"User/Group config file '{CONFIG_FILE_PATH}' initialized/loaded.")
    _db_initialized.set() # Mark as initialized

# Call init_db when the application context is first pushed
# This ensures it runs once when Gunicorn loads the app
with app.app_context():
    init_db()


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# --- Helper Functions for Authentication ---
def get_user_by_username(username):
    """Retrieves a user by username from the SQLite DB."""
    db = get_db()
    return db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

def get_user_by_id(user_id):
    """Retrieves a user by ID from the SQLite DB."""
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

def authenticate_user(username, password):
    """Authenticates a user and returns user ID if successful."""
    user = get_user_by_username(username)
    if user and check_password_hash(user['password_hash'], password):
        return user['id']
    return None

# Decorator for JWT authentication
def login_required(f):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Authentication token missing or invalid'}), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            # Decode and verify the JWT
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            user_id = payload['user_id']
            
            user = get_user_by_id(user_id)
            if user:
                g.user_id = user_id # Store user_id in Flask's global context
                return f(*args, **kwargs)
            else:
                return jsonify({'message': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Authentication token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid authentication token'}), 401
        except Exception as e:
            return jsonify({'message': f'An error occurred during authentication: {e}'}), 500
    wrapper.__name__ = f.__name__ # Preserve original function name for Flask routing
    return wrapper

# --- API Endpoints ---

@app.route('/register', methods=['POST'])
def register():
    """
    Registers a new user in the SQLite database and adds them to the JSON config
    with an empty list of groups.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if get_user_by_username(username):
        return jsonify({'message': 'Username already exists'}), 409

    password_hash = generate_password_hash(password)
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                       (username, password_hash))
        new_user_id = cursor.lastrowid
        db.commit()

        # Add new user to JSON config with no groups initially
        config = load_config()
        config['users'].append({
            "id": new_user_id,
            "username": username,
            "groups": [] # User is not part of any group by default
        })
        save_config(config)

        return jsonify({'message': 'User registered successfully', 'user_id': new_user_id}), 201
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({'message': f'Database error: {e}'}), 500
    except Exception as e:
        return jsonify({'message': f'Error updating config file: {e}'}), 500


@app.route('/login', methods=['POST'])
def login():
    """Logs in a user and returns a JWT."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user_id = authenticate_user(username, password)
    if user_id:
        # Generate JWT
        expires = datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
        token_payload = {
            'user_id': user_id,
            'exp': expires,
            'iat': datetime.utcnow() # Issued at
        }
        token = jwt.encode(token_payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
        
        return jsonify({'message': 'Login successful', 'user_id': user_id, 'token': token}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/submit_location', methods=['POST'])
@login_required
def submit_location():
    """Receives and stores location data for the authenticated user."""
    data = request.get_json()
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    user_id = g.user_id # From login_required decorator

    if latitude is None or longitude is None:
        return jsonify({'message': 'Latitude and longitude are required'}), 400

    timestamp = int(time.time()) # Current Unix timestamp
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('INSERT INTO locations (user_id, timestamp, latitude, longitude) VALUES (?, ?, ?, ?)',
                       (user_id, timestamp, latitude, longitude))
        db.commit()
        return jsonify({'message': 'Location submitted successfully'}), 201
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({'message': f'Database error: {e}'}), 500

@app.route('/get_locations', methods=['POST'])
@login_required
def get_locations():
    """
    Retrieves the latest location for users who share at least one common group
    with the authenticated user, based on the JSON config file.
    """
    requesting_user_id = g.user_id
    
    config = load_config()
    
    requesting_user_groups = []
    requesting_user_username = None
    
    # Find the requesting user's groups from the JSON config
    for user_data in config['users']:
        if user_data['id'] == requesting_user_id:
            requesting_user_groups = user_data.get('groups', [])
            requesting_user_username = user_data.get('username')
            break
            
    if not requesting_user_groups:
        return jsonify({'message': 'You are not part of any groups, so no locations can be shared.'}), 403

    accessible_user_ids = set()
    
    # Find all users who share at least one group with the requesting user
    for other_user_data in config['users']:
        # Don't include self unless explicitly desired (current logic includes self if in a group)
        # If you want to exclude self: if other_user_data['id'] == requesting_user_id: continue
        
        other_user_groups = other_user_data.get('groups', [])
        
        # Check for common groups
        common_groups = set(requesting_user_groups).intersection(set(other_user_groups))
        
        if common_groups:
            accessible_user_ids.add(other_user_data['id'])
            
    if not accessible_user_ids:
        return jsonify({'message': 'No accessible users found in your shared groups.'}), 403

    db = get_db()
    locations = []
    
    # Fetch the latest location for each accessible user
    for target_user_id in accessible_user_ids:
        latest_location = db.execute('''
            SELECT l.latitude, l.longitude, l.timestamp, u.username
            FROM locations l
            JOIN users u ON l.user_id = u.id
            WHERE l.user_id = ?
            ORDER BY l.timestamp DESC
            LIMIT 1
        ''', (target_user_id,)).fetchone()
        
        if latest_location:
            locations.append(dict(latest_location))
            
    return jsonify(locations), 200

# --- Removed Endpoints (as group management is now via JSON file) ---
# @app.route('/create_group', methods=['POST'])
# @app.route('/join_group', methods=['POST'])
# @app.route('/leave_group', methods=['POST'])
# @app.route('/my_groups', methods=['GET'])
# @app.route('/group_members/<int:group_id>', methods=['GET'])


# --- Run the App ---
if __name__ == '__main__':
    # init_db() is now called directly when app context is pushed,
    # so this block is primarily for running the Flask dev server.
    app.run(debug=True) # debug=True for development, turn off for production
