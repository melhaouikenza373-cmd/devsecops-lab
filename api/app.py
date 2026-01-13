from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import subprocess
import re

app = Flask(__name__)

DB_PATH = "users.db"

def get_db():
    return sqlite3.connect(DB_PATH)

# Validation simple
def is_valid_username(username):
    return re.match(r"^[a-zA-Z0-9_]{3,20}$", username)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    if not is_valid_username(username):
        return jsonify({"error": "Invalid username format"}), 400

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()

        if row and bcrypt.checkpw(password.encode(), row[0]):
            return jsonify({"status": "success", "user": username})
        else:
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    except Exception:
        return jsonify({"error": "Internal server error"}), 500

    finally:
        conn.close()

@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json()
    host = data.get("host")

    if not host or not re.match(r"^[a-zA-Z0-9.-]+$", host):
        return jsonify({"error": "Invalid host"}), 400

    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5
        )
        return jsonify({"output": result.stdout})
    except Exception:
        return jsonify({"error": "Ping failed"}), 500

@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Welcome to the secured DevSecOps API"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
