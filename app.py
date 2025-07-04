import sqlite3
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
import os
import time
import jwt # Import the PyJWT library
from datetime import datetime, timedelta # For setting JWT expiration

app = Flask(__name__)
app.config['DATABASE'] = 'location_sharing.db'
app.config['SECRET_KEY'] = os.urandom(24) # Used for session management, but JWT will handle auth
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-jwt-key-please-change-in-production') # IMPORTANT: Use a strong, unique key in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30) # Token valid for 30 days

# --- Database Setup ---
def get_db():
    """Connects to the specific database."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row # This makes rows behave like dictionaries
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database schema."""
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
        # Create groups table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                owner_id INTEGER NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users (id)
            )
        ''')
        # Create group_members table (many-to-many relationship)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                user_id INTEGER NOT NULL,
                group_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, group_id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (group_id) REFERENCES groups (id)
            )
        ''')
        db.commit()
    print("Database initialized.")

# --- Helper Functions for Authentication ---
def get_user_by_username(username):
    """Retrieves a user by username."""
    db = get_db()
    return db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

def get_user_by_id(user_id):
    """Retrieves a user by ID."""
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
    """Registers a new user."""
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
        db.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({'message': f'Database error: {e}'}), 500

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

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    """Creates a new group."""
    data = request.get_json()
    group_name = data.get('name')
    user_id = g.user_id

    if not group_name:
        return jsonify({'message': 'Group name is required'}), 400

    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('INSERT INTO groups (name, owner_id) VALUES (?, ?)',
                       (group_name, user_id))
        group_id = cursor.lastrowid
        # Automatically add the owner to the group
        cursor.execute('INSERT INTO group_members (user_id, group_id) VALUES (?, ?)',
                       (user_id, group_id))
        db.commit()
        return jsonify({'message': 'Group created successfully', 'group_id': group_id}), 201
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({'message': 'Group name already exists'}), 409
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({'message': f'Database error: {e}'}), 500

@app.route('/join_group', methods=['POST'])
@login_required
def join_group():
    """Allows a user to join an existing group."""
    data = request.get_json()
    group_id = data.get('group_id')
    user_id = g.user_id

    if not group_id:
        return jsonify({'message': 'Group ID is required'}), 400

    db = get_db()
    try:
        cursor = db.cursor()
        # Check if group exists
        group = db.execute('SELECT id FROM groups WHERE id = ?', (group_id,)).fetchone()
        if not group:
            return jsonify({'message': 'Group not found'}), 404

        cursor.execute('INSERT INTO group_members (user_id, group_id) VALUES (?, ?)',
                       (user_id, group_id))
        db.commit()
        return jsonify({'message': 'Joined group successfully'}), 200
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({'message': 'Already a member of this group'}), 409
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({'message': f'Database error: {e}'}), 500

@app.route('/leave_group', methods=['POST'])
@login_required
def leave_group():
    """Allows a user to leave a group."""
    data = request.get_json()
    group_id = data.get('group_id')
    user_id = g.user_id

    if not group_id:
        return jsonify({'message': 'Group ID is required'}), 400

    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('DELETE FROM group_members WHERE user_id = ? AND group_id = ?',
                       (user_id, group_id))
        if cursor.rowcount == 0:
            return jsonify({'message': 'Not a member of this group or group not found'}), 404
        db.commit()
        return jsonify({'message': 'Left group successfully'}), 200
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({'message': f'Database error: {e}'}), 500

@app.route('/my_groups', methods=['GET'])
@login_required
def my_groups():
    """Retrieves all groups the authenticated user is a member of."""
    user_id = g.user_id
    db = get_db()
    groups = db.execute('''
        SELECT g.id, g.name, g.owner_id, u.username AS owner_username
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        JOIN users u ON g.owner_id = u.id
        WHERE gm.user_id = ?
    ''', (user_id,)).fetchall()
    
    return jsonify([dict(group) for group in groups]), 200

@app.route('/group_members/<int:group_id>', methods=['GET'])
@login_required
def get_group_members(group_id):
    """Retrieves members of a specific group, if the user is part of that group."""
    user_id = g.user_id
    db = get_db()

    # Check if the requesting user is a member of the group
    is_member = db.execute('SELECT 1 FROM group_members WHERE user_id = ? AND group_id = ?',
                           (user_id, group_id)).fetchone()
    if not is_member:
        return jsonify({'message': 'You are not a member of this group'}), 403

    members = db.execute('''
        SELECT u.id, u.username
        FROM users u
        JOIN group_members gm ON u.id = gm.user_id
        WHERE gm.group_id = ?
    ''', (group_id,)).fetchall()

    return jsonify([dict(member) for member in members]), 200

@app.route('/get_locations', methods=['POST'])
@login_required
def get_locations():
    """
    Retrieves the latest location for users in specified groups that the
    authenticated user is a member of.
    """
    data = request.get_json()
    group_ids = data.get('group_ids', [])
    user_id = g.user_id
    
    if not group_ids:
        return jsonify({'message': 'No group IDs provided'}), 400

    db = get_db()
    accessible_user_ids = set()
    
    # Get all users from the requested groups that the current user is a member of
    for group_id in group_ids:
        # Verify the user is a member of the requested group
        is_member = db.execute('SELECT 1 FROM group_members WHERE user_id = ? AND group_id = ?',
                               (user_id, group_id)).fetchone()
        if is_member:
            group_members = db.execute('SELECT user_id FROM group_members WHERE group_id = ?',
                                       (group_id,)).fetchall()
            for member in group_members:
                accessible_user_ids.add(member['user_id'])
    
    if not accessible_user_ids:
        return jsonify({'message': 'No accessible users found in the specified groups'}), 403

    # Fetch the latest location for each accessible user
    locations = []
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

# --- Run the App ---
if __name__ == '__main__':
    # Initialize the database when the script is run directly
    init_db()
    app.run(debug=True) # debug=True for development, turn off for production
