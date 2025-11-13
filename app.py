from flask import Flask, render_template, request, flash, redirect, url_for, session
from datetime import date
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/add_log', methods=['GET', 'POST'])
def add_log():
    if 'user_id' not in session:
        flash('bro you aint logged in fella', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        date = request.form['date']
        title = request.form['title']
        details = request.form['details']

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                f"INSERT INTO ProgressLogs (user_id, date, title, details) VALUES ('{session['user_id']}', '{date}', '{title}', '{details}')"
            )
            conn.commit()
            flash('Log successfully created!', 'success')
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Invalid entry, please enter all fields', 'error')
            return redirect(url_for('add_log'))
        except Exception as e:
            conn.close()
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('add_log'))

    return render_template('addLog.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('bro you aint logged in fella', 'error')
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/')
def index():
    # return 'Index page'
    return render_template('dashboard.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Insecure: Plain-text password comparison
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, username, hashed_password FROM Users WHERE username = ?", (username,))

        user = cursor.fetchone()
        conn.close()

        if user:
            if check_password_hash(user['hashed_password'] ,password):
                session['user_id'] = user['id']
                flash('Login Successful!', 'success')
            else:
                flash('Invalid Username Or Password', 'error')
                return redirect(url_for('login'))
        else:
            flash('Invalid Username Or Password', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        displayName = request.form['displayName']
        email = request.form['email']
        password = request.form['password']
        confirmPassword = request.form['confirmPassword']
        # hashedPassword = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        if password != confirmPassword:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        try:
            cursor.execute(
                f"INSERT INTO Users (username, hashed_password, email, display_name) VALUES (?, ?, ?, ?)",  (username, generate_password_hash(password), email, displayName)
            )
            conn.commit()
            flash('Registration successful', 'success')
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Username or email already exists', 'error')
            return redirect(url_for('register'))
        except Exception as e:
            conn.close()
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('register'))

        # exists = cursor.execute(f"SELECT COUNT(username) FROM Users WHERE username = '{username}'")
    return render_template('register.html')

@app.route('/view_log', methods=['GET', 'POST'])
def view_log():
    if 'user_id' not in session:
        flash('bro you aint logged in fella', 'error')
        return redirect(url_for('login'))
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor()
        # getting the posts and stuff by checking all posts from a certain user id
        cursor.execute(f"SELECT * FROM ProgressLogs WHERE user_id = '{session['user_id']}' ORDER BY date DESC")
        posts = cursor.fetchall()
        conn.close()

    return render_template('viewLogs.html', posts = posts)


if __name__ == '__main__':
    app.run(debug=True)