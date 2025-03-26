from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_session import Session
import os
import cloudinary
import cloudinary.uploader
import cloudinary.api
import psycopg2
import bcrypt
from dotenv import load_dotenv
from datetime import timedelta
from PIL import Image
import io

load_dotenv()

# Try these exact session settings in your Flask app
app = Flask(__name__)

# Use a strong, random secret key
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", os.urandom(24).hex())

# Session config
app.config['SESSION_TYPE'] = "filesystem"
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Critical cookie settings for cross-origin
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = None  # Not string "None" but Python None
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True only in HTTPS

# Initialize session after configuration
Session(app)

# CORS settings - make sure these match your frontend exactly
CORS(app, 
     supports_credentials=True,
     origins=["http://localhost:5173"],  # Your actual frontend URL
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Database connection
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

# Initialize Cloudinary
cloudinary.config(
    cloud_name=os.getenv("CLOUD_NAME"),
    api_key=os.getenv("API_KEY"),
    api_secret=os.getenv("API_SECRET")
)

# Database connection with error handling
try:
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    print("Database connection established successfully")
except Exception as e:
    print(f"Database connection error: {str(e)}")
    raise

# Create tables
with conn.cursor() as cur:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS talents (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255),
            age INT,
            bio TEXT,
            talent VARCHAR(255),
            phone VARCHAR(20),
            address TEXT,
            country VARCHAR(255),
            state VARCHAR(255),
            district VARCHAR(255),
            profilepic VARCHAR(255),
            userid INT UNIQUE REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    conn.commit()

# @app.before_request
# def check_session():
#     print(f"Request path: {request.path}, Method: {request.method}")
#     print(f"Session before request: {dict(session)}")
#     print(f"Cookies: {request.cookies}")

# @app.after_request
# def add_session_header(response):
#     print(f"Session after request: {dict(session)}")
#     # Add a custom header to debug if session is working
#     if 'user_id' in session:
#         response.headers['X-Session-Status'] = 'active'
#     else:
#         response.headers['X-Session-Status'] = 'inactive'
#     return response

@app.route('/debug-session', methods=['GET'])
def debug_session():
    return jsonify({
        "session_data": dict(session),
        "cookies": {k: v for k, v in request.cookies.items()},
        "headers": {k: v for k, v in request.headers.items()},
        "config": {
            "cookie_name": app.config['SESSION_COOKIE_NAME'],
            "samesite": app.config['SESSION_COOKIE_SAMESITE'],
            "secure": app.config['SESSION_COOKIE_SECURE']
        }
    }), 200

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        # Retrieve user from database
        with conn.cursor() as cur:
            cur.execute("SELECT id, password FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            print(f"User found: {user}")
            
        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            # Clear any existing session data first
            session.clear()
            
            # Set session data
            session.permanent = True
            session['user_id'] = user[0]
            session['username'] = username
            session.modified = True
            
            print(f"Session data after login: {dict(session)}")
            
            return jsonify({
                "message": "Login successful!", 
                "username": username, 
                "status": "success"
            }), 200
        else:
            return jsonify({"message": "Invalid credentials", "status": "error"}), 401
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/users', methods=['GET'])
def get_users():
    try:
        print(f"Session in users route: {dict(session)}")
        
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM talents")
            users = cur.fetchall()

        users_list = []
        for user in users:
            user_dict = {
                "id": user[0],
                "name": user[1],
                "age": user[2],
                "bio": user[3],
                "talent": user[4],
                "phone": user[5],
                "address": user[6],
                "country": user[7],
                "state": user[8],
                "district": user[9],
                "profilepic": user[10],
                "userid": user[11]
            }
            users_list.append(user_dict)

        return jsonify(users_list), 200
    except Exception as e:
        print(f"Get users error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/profile", methods=["GET", "PUT"])
@app.route("/profile/<int:user_id>", methods=["GET", "PUT"])  # Handle specific user profile via URL
def profile(user_id=None):
    # If no user_id is provided in the URL, use the logged-in user's id from the session
    if user_id is None:
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized - No user_id in session"}), 401
        user_id = session["user_id"]

    try:
        if request.method == "GET":
            # Fetch user details from the database
            print(f"Fetching profile for user: {user_id}")
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM talents WHERE userid = %s", (user_id,))
                user = cur.fetchone()
            
            if user:
                user_data = {
                    "id": user[0],
                    "name": user[1],
                    "age": user[2],
                    "bio": user[3],
                    "talent": user[4],
                    "phone": user[5],
                    "address": user[6],
                    "country": user[7],
                    "state": user[8],
                    "district": user[9],
                    "profilepic": user[10],
                    "userid": user[11]
                }
                return jsonify(user_data), 200
            else:
                return jsonify({"error": "User profile not found"}), 404

        # PUT request handling (e.g., updating the user's profile) would go here
        # Example:
        # elif request.method == "PUT":
        #     # Update profile logic
        #     return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        print(f"Profile error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    
@app.route("/session", methods=["GET"])
def check_session():
    if "user_id" in session:
        return jsonify({"userId": session["user_id"], "username": session.get("username")}), 200
    else:
        return jsonify({"error": "User not logged in"}), 401

from PIL import Image, ExifTags
import io
import cloudinary.uploader

def compress_and_upload(file, folder_name):
    """Compress image, auto-rotate if needed, and upload to Cloudinary in a separate thread."""
    try:
        # Open image
        image = Image.open(file)
        image = image.convert("RGB")  # Ensure compatibility

        # Fix rotation based on EXIF data
        try:
            exif = image._getexif()
            if exif:
                for tag, value in exif.items():
                    tag_name = ExifTags.TAGS.get(tag, tag)
                    if tag_name == "Orientation":
                        if value == 3:
                            image = image.rotate(180, expand=True)
                        elif value == 6:
                            image = image.rotate(270, expand=True)
                        elif value == 8:
                            image = image.rotate(90, expand=True)
        except (AttributeError, KeyError, IndexError):
            pass  # No EXIF data found, continue normally

        # Resize image (max width/height 800px)
        max_size = (800, 800)
        image.thumbnail(max_size, Image.LANCZOS)

        # Save to memory with compression
        img_io = io.BytesIO()
        image.save(img_io, format="JPEG", quality=70)  # Compress to 70% quality
        img_io.seek(0)

        # Upload to Cloudinary
        upload_result = cloudinary.uploader.upload(img_io, folder=folder_name)
        file_url = upload_result.get("secure_url")
        print(file_url)
        return file_url  # Return the uploaded file URL

    except Exception as e:
        print(f"Cloudinary Upload Error: {str(e)}")

        return None

        
        
@app.route('/register', methods=['POST'])
def register():
    try:
        # Retrieve form fields
        name = request.form.get("name")
        age = request.form.get("age")
        bio = request.form.get("bio")
        talent = request.form.get("talent")
        phone = request.form.get("phone")
        address = request.form.get("address")
        country = request.form.get("country")
        state = request.form.get("state")
        district = request.form.get("district")
        profilepic=request.form.get("profilepic")
        # Handle profile picture upload
        file = request.files.get("image")
        
        if file:
            folder_name = 'Profile_pics'
            #upload_result = cloudinary.uploader.upload(file, folder=folder_name)
            file_url = compress_and_upload(file,folder_name)
        else:
            file_url = profilepic

        # Check if user is logged in
        if 'user_id' not in session:
            return jsonify({"error": "User not logged in"}), 401
            
        user_id = session['user_id']
        
        with conn.cursor() as cur:
            # Check if profile already exists for user
            cur.execute("SELECT id FROM talents WHERE userid = %s", (user_id,))
            existing = cur.fetchone()
            
            if existing:
                # Update existing profile
                cur.execute("""
                    UPDATE talents 
                    SET name = %s, age = %s, bio = %s, talent = %s, 
                        phone = %s, address = %s, country = %s, 
                        state = %s, district = %s, profilepic = %s
                    WHERE userid = %s
                """, (name, age, bio, talent, phone, address, country, state, district, file_url, user_id))
            else:
                # Insert new profile
                cur.execute("""
                    INSERT INTO talents (name, age, bio, talent, phone, address, country, state, district, profilepic, userid)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (name, age, bio, talent, phone, address, country, state, district, file_url, user_id))
            
            conn.commit()

        return jsonify({"message": "Profile updated successfully", "profile_pic": file_url}), 200
    except Exception as e:
        print(f"Register error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        name = username
        
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (username, email, password) 
                VALUES (%s, %s, %s) RETURNING id
            """, (username, email, hashed_password))
            user_id = cur.fetchone()[0]

            cur.execute("""
                INSERT INTO talents (userid, name) 
                VALUES (%s, %s)
            """, (user_id, name))

            conn.commit()

        return jsonify({
            "message": "User registered successfully!", 
            "status": "success", 
            "user_id": user_id
        }), 201
    except Exception as e:
        print(f"Signup error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/logout', methods=['POST'])
def logout():
    print(f"Session before logout: {dict(session)}")
    session.clear()
    print(f"Session after logout: {dict(session)}")
    return jsonify({"message": "Logged out successfully"}), 200


if __name__ == '__main__':
    app.run(debug=True)