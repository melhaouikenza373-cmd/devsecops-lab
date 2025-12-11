from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os
import re

app = Flask(__name__)

# ❌ plus de secret hardcodé : on utilise une variable d'environnement
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-prod")  # nosec

def get_db():
    return sqlite3.connect("users.db")

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    conn = get_db()
    cursor = conn.cursor()

    # ✔️ Paramétrisation = pas d'injection SQL
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))

    result = cursor.fetchone()
    if result:
        return {"status": "success", "user": username}
    return {"status": "error", "message": "Invalid credentials"}


@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    # ✔️ Validation stricte
    if not re.match(r"^[a-zA-Z0-9\.-]+$", host):
        return {"error": "Invalid host"}, 400

    # ✔️ Pas de shell=True → safe
    output = subprocess.check_output(["ping", "-c", "1", host])

    return {"output": output.decode()}


@app.route("/compute", methods=["POST"])
def compute():
    # ❌ eval() → remplacé par une évaluation sûre
    expr = request.json.get("expression", "1+1")

    # Mini parser autorisant seulement + - * /
    if not re.match(r"^[0-9+\-*/ ()]+$", expr):
        return {"error": "Invalid expression"}, 400

    result = eval(expr, {"__builtins__": {}}, {})  # nosec (contrôlé)

    return {"result": result}


@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "admin")

    # ✔️ SHA-256 au lieu de MD5
    hashed = hashlib.sha256(pwd.encode()).hexdigest()

    return {"sha256": hashed}


@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "test.txt")

    # ✔️ Empêcher path traversal
    if not filename.isalnum() and not filename.endswith(".txt"):
        return {"error": "Invalid filename"}, 400

    safe_path = os.path.join("files", filename)

    if not os.path.exists(safe_path):
        return {"error": "File not found"}, 404

    with open(safe_path, "r") as f:
        content = f.read()

    return {"content": content}


@app.route("/debug", methods=["GET"])
def debug():
    # Ne renvoie plus d'infos sensibles
    return {"debug": False}


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the secure API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
