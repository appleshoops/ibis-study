from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import login_required, LoginManager, UserMixin, current_user, login_user, logout_user
import sqlite3
import logging  # library for logging security events
import bleach  # library for sanitisation of data
from email_validator import validate_email, EmailNotValidError
from zxcvbn import zxcvbn  # password rules
from forms import RegistrationForm, LoginForm, AddProgressForm  # importing classes from forms file
from flask_wtf import FlaskForm  # library to allow use of wtforms
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField  # fields for forms
from wtforms.validators import DataRequired, Length, Email  # validation types within forms
from flask_wtf.csrf import CSRFProtect  # allowing CSRF protection
from contextlib import contextmanager
import os
from dotenv import load_dotenv

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("No FLASK_SECRET_KEY set in environment or .env file!")

# enable csrf protection
csrf = CSRFProtect(app)

# initialise flask login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page"
login_manager.login_message_category = 'error'

# user class for flask login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# cleaning inputs
def clean_input(s: str, allow_html: bool = False) -> str:
    s = s.strip()
    if allow_html:
        return bleach.clean(
            s,
            tags=['p', 'br', 'strong', 'en'],
            attributes={},
            strip=True
        )
    else:
        return bleach.clean(s, tags=[], strip=True)

def clean_log_title(s: str, allow_html: bool = False) -> str:
    # strip all dangerous content
    s = s.strip()
    # remove all HTML
    cleaned = bleach.clean(s, tags=[], strip=True)
    return cleaned[:100]

def clean_log_details(s: str) -> str:
    s = s.strip()
    return bleach.clean(
        s,
        tags=['p', 'br', 'strong', 'en', 'ul', 'ol', 'li', 'u'],
        attributes={},
        strip=True
    )

# check email validity instead of native HTML checking
def validate_email_strict(email: str) -> tuple[bool, str]:
    try:
        validate_email(email, check_deliverability=False)
        return True, ""
    except EmailNotValidError as e:
        return False, str(e)

def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 10:
        return False, "Password must be at least 10 characters long"

    result = zxcvbn(password)
    if result['score'] < 3:
        warning = result['feedback']['warning'] or "Password is too weak"
        suggestions = " ".join(result['feedback']['suggestions'])
        return False, f"{warning} {suggestions}".strip()
    return True, "Strong password"

@login_manager.user_loader
def load_user(user_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, username FROM Users WHERE id = ?',
                (user_id,)
            )
            user = cursor.fetchone()

        if user:
            return User(id=user['id'], username=user['username'])
        return None

    except Exception as e:
        # Log the error in development, but don't expose it to user
        print(f"Error loading user {user_id}: {e}")  # Replace with proper logging later
        return None


@contextmanager
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    try: # waits for the connection to finish, keeping it open until it is done so it can be closed
        yield conn
    finally:
        conn.close()
@app.route('/add_progress', methods=['GET', 'POST'])
@login_required
def add_progress():
    form = AddProgressForm()

    if form.validate_on_submit():
        date_str = form.date.data.strftime('%Y-%m-%d')   # Convert date to string
        title = clean_log_title(form.title.data)
        details = clean_log_details(form.details.data)

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO ProgressLogs (user_id, date, title, details) VALUES (?, ?, ?, ?)",
                    (current_user.id, date_str, title, details)
                )
                conn.commit()

            flash('Progress log added successfully!', 'success')
            return redirect(url_for('view_log'))

        except Exception as e:
            flash('An error occurred while saving your progress.', 'error')

    return render_template('addProgress.html', form=form, username=current_user.username)
@app.route('/create_question', methods=['GET', 'POST'])
@login_required
def createQuestion():
    quiz_data = None
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT title, numQuestions FROM Quizzes WHERE id = ?", (session['created_quiz_id'],))
        quiz_data = cursor.fetchone()
        conn.close()

    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT numQuestions FROM Quizzes WHERE id = ?", (session['created_quiz_id'],))
        quiz_data = cursor.fetchone()

        num_questions = quiz_data['numQuestions']
        for i in range(num_questions):
            question = request.form.get(f'question_{i}')
            choices = [request.form.get(f'choice_{i}_{j}') for j in range(4)]
            correct_index = int(request.form.get(f'correct_{i}'))

            if not question or not all(choices):
                conn.close()
                flash(f'Please fill out all fields for question {i+1}.', 'error')
                return redirect(url_for('createQuestion'))

            try:
                cursor.execute(
                    "INSERT INTO Questions (quiz_id, question, choice1, choice2, choice3, choice4, correct_index) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (session['created_quiz_id'], question, choices[0], choices[1], choices[2], choices[3], correct_index)
                )
            except sqlite3.IntegrityError:
                conn.close()
                flash('Invalid entry, please enter all fields', 'error')
                return redirect(url_for('createQuestion'))
            except Exception as e:
                conn.close()
                flash(f'Error: {str(e)}', 'error')
                return redirect(url_for('createQuestion'))

        conn.commit()
        conn.close()
        flash('Questions successfully created!', 'success')
        return redirect(url_for('quizSelect'))
    return render_template('questionCreate.html', quiz=quiz_data)

@app.route('/create_quiz', methods=['GET', 'POST'])
@login_required
def createQuiz():
    if request.method == 'POST':
        title = request.form['quizName']
        description = request.form['quizDescription']
        numQuestions = request.form['quizQuestions']

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO Quizzes (title, description, numQuestions, user_id) VALUES (?, ?, ?, ?)", (title, description, numQuestions, current_user.id)
            )
            quiz_id = cursor.lastrowid
            conn.commit()
            session['created_quiz_id'] = quiz_id
            return redirect(url_for('createQuestion'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Invalid entry, please enter all fields', 'error')
        except Exception as e:
            conn.close()
            flash(f'Error: {str(e)}', 'error')

    return render_template('quizCreate.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/flashcard_set_select', methods=['GET', 'POST'])
@login_required
def flashcardSetSelect():
    flashcard_sets = None
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM FlashcardSet")
        flashcard_sets = cursor.fetchall()
        conn.close()
    return render_template('flashcardSelect.html', flashcard_sets=flashcard_sets)

@app.route('/flashcard_create', methods=['GET', 'POST'])
@login_required
def flashcardCreate():
    flashcardData = None
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT title, flashcardNumber FROM FlashcardSet WHERE id = ?", (session['created_flashcard_set_id'],))
        flashcardData = cursor.fetchone()
        conn.close()

    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT flashcardNumber FROM FlashcardSet WHERE id = ?", (session['created_flashcard_set_id'],))
        flashcardData = cursor.fetchone()

        num_questions = flashcardData['flashcardNumber']
        for i in range(num_questions):
            front = request.form.get(f'front_{i}')
            back = request.form.get(f'back_{i}')

            if not front or not back:
                conn.close()
                flash(f'Please fill out all fields for question {i+1}.', 'error')

            try:
                cursor.execute(
                    "INSERT INTO Flashcards (set_id, front, back) VALUES (?, ?, ?)",
                    (session['created_flashcard_set_id'], front, back,)
                )
            except sqlite3.IntegrityError:
                conn.close()
                flash('Invalid entry, please enter all fields', 'error')
                return redirect(url_for('flashcardCreate'))
            except Exception as e:
                conn.close()
                flash(f'Error: {str(e)}', 'error')
                return redirect(url_for('flashcardCreate'))
        conn.commit()  # <-- Make sure to commit here so inserts persist!
        conn.close()
        flash('Flashcards successfully created!', 'success')
        return redirect(url_for('flashcardSetSelect'))

    return render_template('flashcardCreate.html', flashcardSet=flashcardData)

@app.route('/flashcard_set_delete', methods=['POST', 'GET'])
@login_required
def flashcardSetDelete():
    set_id = request.args.get('set_id', type=int)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM FlashcardSet WHERE id = ?", (set_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('flashcardSetSelect'))



@app.route('/flashcard_set_create', methods=['GET', 'POST'])
@login_required
def flashcardSetCreate():
    if request.method == 'POST':
        title = request.form['flashcardSetName']
        description = request.form['flashcardSetDescription']
        flashcardNumber = request.form['flashcardNumber']

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO FlashcardSet (title, description, flashcardNumber, user_id) VALUES (?, ?, ?, ?)", (title, description, flashcardNumber, current_user.id)
            )
            flashcard_set_id = cursor.lastrowid
            conn.commit()
            session['created_flashcard_set_id'] = flashcard_set_id
            return redirect(url_for('flashcardCreate'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Invalid entry, please enter all fields', 'error')
        except Exception as e:
            conn.close()
            flash(f'Error: {str(e)}', 'error')

    return render_template('flashcardSetCreate.html')
@app.route('/flashcards')
@login_required
def flashcards():
    set_id = request.args.get('set_id', type=int)
    if not set_id:
        flash('No flashcard set selected.', 'error')
        return redirect(url_for('flashcardSetSelect'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get the set info
    cursor.execute("SELECT title, description FROM FlashcardSet WHERE id = ?", (set_id,))
    set_data = cursor.fetchone()

    # Get the flashcards for this set
    cursor.execute("SELECT front, back FROM Flashcards WHERE set_id = ?", (set_id,))
    flashcards = cursor.fetchall()
    conn.close()

    if set_data is None:
        flash('Flashcard set not found.', 'error')
        return redirect(url_for('flashcardSetSelect'))

    return render_template('flashcards.html', set_title=set_data['title'], set_description=set_data['description'], flashcards=flashcards)
@app.route('/')
def index():
    # return 'Index page'
    return render_template('dashboard.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()  # reference to the login form class

    if form.validate_on_submit():  # run the following code if the data in it is valid
        username = form.username.data.strip()  # cleaning the username and storing it
        password = form.password.data

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # check if user exists - if so return id, username, hashed pw
                cursor.execute(
                    "SELECT id, username, hashed_password FROM Users WHERE username = ?",
                    (username,)
                )
                user_row = cursor.fetchone()

            # if user exists and passwords match
            if user_row and check_password_hash(user_row['hashed_password'], password):
                user = User(id=user_row['id'], username=user_row['username'])
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')

        except Exception as e:
            flash('An error occurred during login. Please try again.', 'error')

    return render_template('login.html', form=form)

@app.route('/quiz', methods=['GET', 'POST'])
@login_required
def quiz():
    if request.method == 'GET':
        quiz_id = request.args.get('quiz_id', type=int)
        if not quiz_id:
            flash('Invalid quiz ID', 'error')
            return redirect(url_for('quizSelect'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT Quizzes.id AS quiz_id, Quizzes.title AS quiz_title, Quizzes.description AS quiz_description, Questions.* FROM Quizzes JOIN Questions ON Questions.quiz_id = Quizzes.id WHERE Quizzes.id = ?", (quiz_id,))
        quiz_data = cursor.fetchall()
        conn.close()

        if not quiz_data:
            flash('Quiz has no questions', 'error')
            return redirect(url_for('quizSelect'))
        quiz_info = {
            'quiz_id': quiz_id,
            'quiz_title': quiz_data[0]['quiz_title'],
            'quiz_description': quiz_data[0]['quiz_description'],
        }
        questions = []
        for question in quiz_data:
            questions.append({
                'id': question['id'],
                'question': question['question'],
                'choice1': question['choice1'],
                'choice2': question['choice2'],
                'choice3': question['choice3'],
                'choice4': question['choice4'],
                'correct_index': int(question['correct_index']) - 1
            })

    return render_template('quiz.html', username=current_user.username, quiz=quiz_info, questions=questions)

@app.route('/quiz_delete', methods=['POST', 'GET'])
@login_required
def quizDelete():
    quiz_id = request.args.get('quiz_id', type=int)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Quizzes WHERE id = ?", (quiz_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('quizSelect'))
@app.route('/quiz_results', methods=['POST'])
@login_required
def quizResults():
    quiz_id = request.form.get('quiz_id', type=int)
    if not quiz_id:
        flash('No quiz selected', 'error')
        return redirect(url_for('quizSelect'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Questions WHERE quiz_id = ?", (quiz_id,))
    questions = cursor.fetchall()
    conn.close()

    results = []
    num_correct = 0

    for question in questions:
        question_id = question['id']
        correct_index = int(question['correct_index'])
        user_answer = request.form.get(f'answer_{question_id}')
        user_answer_index = int(user_answer) if user_answer is not None else None

        is_correct = (user_answer_index == correct_index)
        if is_correct:
            num_correct += 1

        results.append({
            'question': question['question'],
            'choice1': question['choice1'],
            'choice2': question['choice2'],
            'choice3': question['choice3'],
            'choice4': question['choice4'],
            'user_answer': user_answer_index,
            'correct_index': correct_index,
            'is_correct': is_correct,
        })

    total_questions = len(questions)
    score = f"{num_correct}/{total_questions}" if total_questions > 0 else "0/0"
    points = int(total_questions * 10)

    return render_template(
        'quizResults.html',
        username=getattr(current_user, "username", None),
        results=results,
        score=score,
        points=points,
        quiz_id=quiz_id
    )

@app.route('/select_quiz', methods=['GET', 'POST'])
@login_required
def quizSelect():
    quiz_data = None
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Quizzes")
        quiz_data = cursor.fetchall()
        conn.close()

    return render_template('quizSelect.html', quizzes=quiz_data, user_id=session.get('user_id'))

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    logout_user()
    flash('You have successfully logged out, come back soon!', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        username = clean_input(form.username.data)
        displayName = clean_input(form.displayName.data)
        email = clean_input(form.email.data)
        password = form.password.data

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                hashed_password = generate_password_hash(password)

                cursor.execute(
                    """INSERT INTO Users (username, hashed_password, email, display_name)
                       VALUES (?, ?, ?, ?)""",
                    (username, hashed_password, email, displayName)
                )
                conn.commit()

                cursor.execute("SELECT id, username FROM Users WHERE username = ?", (username,))
                user_row = cursor.fetchone()

            if user_row:
                new_user = User(id=user_row['id'], username=user_row['username'])
                login_user(new_user)
                flash('Registration successful! Welcome!', 'success')
                return redirect(url_for('dashboard'))

        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'error')
        except Exception as e:
            flash('An unexpected error occurred. Please try again.', 'error')

    return render_template('register.html', form=form)

@app.route('/view_log', methods=['GET'])
@login_required
def view_log():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT date, title, details
                FROM ProgressLogs
                WHERE user_id = ?
                ORDER BY date DESC
                """,
                (current_user.id,)
            )
            posts = cursor.fetchall()

        return render_template('viewLogs.html', posts=posts, username=current_user.username)

    except Exception as e:
        flash(f'Error loading your progress logs: {e}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/update_score_and_home', methods=['POST'])
@login_required
def update_score_and_home():
    points = request.form.get('points', type=int)
    if points is not None:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE Users SET score = score + ? WHERE id = ?", (points, current_user.id))
        conn.commit()
        conn.close()
    return redirect(url_for('dashboard'))

@app.route('/sdlc_docs')
def sdldocs():
    return render_template('sdlc.html')
if __name__ == '__main__':
    app.run(debug=True)
