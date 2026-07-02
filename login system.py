import os
import sqlite3
import hashlib

from flask import Flask, request, redirect, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "mysecretkey")
DATABASE_PATH = os.getenv("DATABASE_PATH", "users.db")


def get_connection():
    return sqlite3.connect(DATABASE_PATH)


def init_db():
    with get_connection() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            password TEXT
        )
        """)
        conn.commit()


# Hash password
def hash_password(password):
    return generate_password_hash(password)


def legacy_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()


def is_legacy_password_hash(stored_password):
    return len(stored_password) == 64 and all(
        character in "0123456789abcdef" for character in stored_password
    )


def password_matches(stored_password, submitted_password):
    if is_legacy_password_hash(stored_password):
        return stored_password == legacy_sha256(submitted_password)
    return check_password_hash(stored_password, submitted_password)


init_db()

# Home
@app.route("/")
def home():
    if "user" in session:
        return f"""
        <h2>Welcome {session['user']}</h2>
        <a href='/logout'>Logout</a>
        """
    return redirect("/login")

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if username == "" or password == "":
            return "All fields are required."

        hashed = hash_password(password)

        try:
            with get_connection() as conn:
                conn.execute("INSERT INTO users VALUES(?,?)", (username, hashed))
                conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists."
        return redirect("/login")

    return """
    <h2>Register</h2>
    <form method='post'>
        Username:<br>
        <input name='username'><br><br>
        Password:<br>
        <input type='password' name='password'><br><br>
        <input type='submit' value='Register'>
    </form>
    <br>
    <a href='/login'>Login</a>
    """

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cur.fetchone()

            if user and password_matches(user[1], password):
                if is_legacy_password_hash(user[1]):
                    conn.execute(
                        "UPDATE users SET password=? WHERE username=?",
                        (hash_password(password), username),
                    )
                    conn.commit()
                session["user"] = username
                return redirect("/")

        return "Invalid Username or Password."

    return """
    <h2>Login</h2>
    <form method='post'>
        Username:<br>
        <input name='username'><br><br>
        Password:<br>
        <input type='password' name='password'><br><br>
        <input type='submit' value='Login'>
    </form>
    <br>
    <a href='/register'>Register</a>
    """

# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)
