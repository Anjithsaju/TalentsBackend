from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_session import Session  # Import flask-session
import os

from flask import make_response

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import cloudinary
import cloudinary.uploader
import cloudinary.api
import psycopg2
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, session
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "your_secret_key"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # ❌ Set to False for local testing
    SESSION_COOKIE_SAMESITE="None",  # ✅ Important for cross-origin requests
    SESSION_PERMANENT=True,
)

CORS(
    app,
    supports_credentials=True,  # ✅ Allows cookies to be sent
    origins="http://localhost:5173",  # ✅ React frontend
)



# Database credentials
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

# Connect to database
conn = psycopg2.connect(
    dbname=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT
)

cur = conn.cursor()
# Create tables if they don't exist
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
        profilepic VARCHAR(255)
    )
""")
conn.commit()



@app.before_request
def before_request():
    if request.method == "OPTIONS":
        return make_response("", 200)  # Skip session handling
    session.permanent = True

@app.route('/users', methods=['GET'])
def get_users():
    try:
        print(session)
        
        # Query the database to fetch all users
        cur.execute("SELECT * FROM talents")
        users = cur.fetchall()

        # Convert the result to a list of dictionaries
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
                "profilepic": user[10]  # URL to profile picture
            }
            users_list.append(user_dict)

        # Return the list of users as JSON
        return jsonify(users_list), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/profile", methods=["GET"])
def profile():
    
    print("Session Data:1", session)  # Debugging
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401  # Issue here

    return jsonify({
        "user_id": session["user_id"],
        "username": session["username"]
    })

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

        # Handle profile picture upload
        file = request.files.get("image")
        
        if file:
            # Define the folder in Cloudinary where you want to store the image
            folder_name = 'Profile_pics'  # Change this to your desired folder name
            
            # Upload the file to Cloudinary with the folder specified
            upload_result = cloudinary.uploader.upload(file, folder=folder_name)
            
            # Get the secure URL of the uploaded image
            file_url = upload_result.get("secure_url")
        else:
            file_url = None  # If no file is uploaded

        # Insert into database (no need to provide the 'id' field)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO talents (name, age, bio, talent, phone, address, country, state, district, profilepic)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (name, age, bio, talent, phone, address, country, state, district, file_url))
            conn.commit()

        return jsonify({"message": "Registration successful", "profile_pic": file_url}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# User Registration
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        # Hash the password before storing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Insert into database
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (username, email, password) 
                VALUES (%s, %s, %s)
            """, (username, email, hashed_password))
            conn.commit()

        return jsonify({"message": "User registered successfully!", "status": "success"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# User Login


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

        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            session['user_id'] = user[0]
            session['username'] = username
            session.modified = True  # Ensure session data is updated
            print("Session Data After Login:", dict(session))  # Debugging

            return jsonify({"message": "Login successful!", "username": username, "status": "success"}), 200
        else:
            return jsonify({"message": "Invalid credentials", "status": "error"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500






@app.route('/logout', methods=['POST'])
def logout():
    session.pop("user", None)  # Remove user from session
    return jsonify({"message": "Logged out successfully"}), 200



if __name__ == '__main__':
    app.run(debug=True)
