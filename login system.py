from flask import Flask, request, redirect, session

import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "mysecretkey"

# Create database
conn = sqlite3.connect("users.db")
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY,
    password TEXT
)
""")
conn.commit()
conn.close()

# Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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
            conn = sqlite3.connect("users.db")
            cur = conn.cursor()
            cur.execute("INSERT INTO users VALUES(?,?)", (username, hashed))
            conn.commit()
            conn.close()
            return redirect("/login")
        except:
            return "Username already exists."

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
        password = hash_password(request.form["password"])

        conn = sqlite3.connect("users.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cur.fetchone()
        conn.close()

        if user:
            session["user"] = username
            return redirect("/")
        else:
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