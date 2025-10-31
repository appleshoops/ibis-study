from flask import Flask, render_template, request
import sqlite3

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    # return 'Index page'
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    if request.method == 'POST':
        username = request.form['username']
        displayName = request.form['displayName']
        email = request.form['email']
        password = request.form['password']
        conformPassword = request.form['confirmPassword']

        conn = get_db_connection()
        cursor = conn.cursor()

        exists = cursor.execute(f"SELECT COUNT(username) FROM Users WHERE username = '{username}'")
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)