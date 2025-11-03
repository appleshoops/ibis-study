from flask import Flask, render_template, request, flash, redirect, url_for
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        displayName = request.form['displayName']
        email = request.form['email']
        password = request.form['password']
        confirmPassword = request.form['confirmPassword']

        conn = get_db_connection()
        cursor = conn.cursor()

        if password != confirmPassword:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))

        # exists = cursor.execute(f"SELECT COUNT(username) FROM Users WHERE username = '{username}'")
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)