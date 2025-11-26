from optparse import Values

from flask import Flask, render_template, request, flash, redirect, url_for, session
from datetime import date
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from flask_login import login_required, LoginManager, UserMixin, current_user, login_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page"
login_manager.login_message_category = 'error'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM Users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    if User:
        return User(id=user['id'], username=user['username'])
    return None

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/add_log', methods=['GET', 'POST'])
@login_required
def add_log():
    """
    if 'user_id' not in session:
        flash('You are not logged in', 'error')
        return redirect(url_for('login'))
    """
    if request.method == 'POST':
        date = request.form['date']
        title = request.form['title']
        details = request.form['details']

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO ProgressLogs (user_id, date, title, details) VALUES (?, ?, ?, ?)", (current_user.id, date, title, details)
            )
            conn.commit()
            flash('Log successfully created!', 'success')
            return redirect(url_for('view_log'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Invalid entry, please enter all fields', 'error')
        except Exception as e:
            conn.close()
            flash(f'Error: {str(e)}', 'error')

    return render_template('addLog.html', username=current_user.username)
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
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT display_name, score FROM Users WHERE id = ?", (current_user.id,))
    user_data = cursor.fetchone()
    conn.close()
    display_name = user_data['display_name'] if user_data and 'display_name' in user_data else current_user.username
    total_score = user_data['total_score'] if user_data and 'total_score' in user_data else 0
    return render_template('dashboard.html', display_name=display_name, total_score=total_score)

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
                login_user(User(id=user['id'], username=user['username']))
                flash('Login Successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid Username Or Password', 'error')
                return redirect(url_for('login'))
        else:
            flash('Invalid Username Or Password', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

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
            # add the user to the users sql database
            cursor.execute(
                f"INSERT INTO Users (username, hashed_password, email, display_name) VALUES (?, ?, ?, ?)",  (username, generate_password_hash(password), email, displayName)
            )
            conn.commit()
            flash('Registration successful', 'success')
            # automatically log the user in
            cursor.execute("SELECT id, username, hashed_password FROM Users WHERE username = ?", (username,))
            user = cursor.fetchone()
            login_user(User(id=user['id'], username=user['username']))
            conn.close()
            return redirect(url_for('dashboard'))
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
@login_required
def view_log():
    """if 'user_id' not in session:
        flash('You are not currently logged in', 'error')
        return redirect(url_for('login'))"""
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor()
        # getting the posts and stuff by checking all posts from a certain user id
        cursor.execute("SELECT date, title, details FROM ProgressLogs WHERE user_id = ? ORDER BY DATE DESC", (current_user.id,))
        posts = cursor.fetchall()
        conn.close()

    return render_template('viewLogs.html', posts = posts, username=current_user.username)

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
