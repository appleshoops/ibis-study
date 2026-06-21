from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask_login import login_required, LoginManager, UserMixin, current_user, login_user, logout_user
import sqlite3
import logging  # library for logging security events
import bleach  # library for sanitisation of data
import yfinance as yf
import plotly.express as px
import plotly.io as pio
from email_validator import validate_email, EmailNotValidError
from zxcvbn import zxcvbn  # password rules
from forms import RegistrationForm, LoginForm, AddProgressForm, QuoteForm  # importing classes from forms file
from flask_wtf import FlaskForm  # library to allow use of wtforms
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField  # fields for forms
from wtforms.validators import DataRequired, Length, Email  # validation types within forms
from flask_wtf.csrf import CSRFProtect  # allowing CSRF protection
from contextlib import contextmanager
import os
from dotenv import load_dotenv
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("No FLASK_SECRET_KEY set in environment or .env file!")

# enable csrf protection
csrf = CSRFProtect(app)

UPLOAD_FOLDER = 'static/upload'
ALLOWED_EXTENTIONS = ['png', 'jpg', 'jpeg', 'gif', 'webp']
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # create uploads folder if it doesn't exist

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

def clean_log_title(s: str) -> str:
    # strip all dangerous content
    s = s.strip()
    # remove all HTML
    cleaned = bleach.clean(s, tags=[], strip=True)
    return cleaned[:100]

# strip all logs of dangerous characters
def clean_log_details(s: str) -> str:
    s = s.strip()
    return bleach.clean(
        s,
        tags=['p', 'br', 'strong', 'en', 'ul', 'ol', 'li', 'u'], # only allow certain tags related to the log details
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

# makes sure passwords meet security requirements
def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 10: # makes sure passwords are at least 10 characters long for security
        return False, "Password must be at least 10 characters long"

    result = zxcvbn(password)
    if result['score'] < 3: # feeds password into zxcvbn module and makes sure it reaches a certain level of security
        warning = result['feedback']['warning'] or "Password is too weak"
        suggestions = " ".join(result['feedback']['suggestions']) # gives a suggestion to increase password security
        return False, f"{warning} {suggestions}".strip()
    return True, "Strong password"


# creates login manager
@login_manager.user_loader
def load_user(user_id):
    try:
        # checks if user exists in SQL table
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

def get_stock_info(ticker: str):
    if not ticker or len(ticker.strip()) < 1:  # if ticker name is too short
        return None, None, "Please enter a valid ticker symbol"

    ticker = ticker.upper().strip()  # convert to uppercase, remove any unwanted spaces

    try:
        stock = yf.Ticker(ticker)
        info = stock.info

        # Current price -- get the first price found then exit loop
        current_price = None  # initialise current price
        for key in ['currentPrice', 'regularMarketPrice', 'price']:
            if info.get(key):
                current_price = info.get(key)
                break

        stock_data = {
            'ticker': ticker,
            'name': info.get('longName') or info.get('shortName') or f"{ticker} Stock",
            'current_price': round(current_price, 2) if current_price else None,
            'previous_close': round(info.get('regularMarketPreviousClose', 0), 2),
            'market_cap': info.get('marketCap'),
            'currency': info.get('currency', 'USD'),
            'summary': info.get('longBusinessSummary'),
            'last_updated': datetime.now().strftime("%Y-%m-%d %H:%M")
        }

        # Get historical data for chart (last 3 months)
        hist = stock.history(period="3mo")
        chart_data = None

        if not hist.empty:
            chart_data = {
                'dates': hist.index.strftime('%Y-%m-%d').tolist(),
                'close': hist['Close'].round(2).tolist()
            }

        return stock_data, chart_data, None

    except Exception as e:
        print(f"Error fetching {ticker}: {e}")
        return None, None, f"Failed to fetch data for {ticker}. Please try again."
@app.route('/add_progress', methods=['GET', 'POST'])
@login_required
def add_progress():
    form = AddProgressForm()  # for prevention of CSRF

    if form.validate_on_submit():
        date_str = form.date.data.strftime('%Y-%m-%d')   # Convert date to string
        title = clean_log_title(form.title.data)  # input sanitisation
        details = clean_log_details(form.details.data)

        # Uploading images
        image_path = None  # initialising image_path
        if form.image.data and form.image.data.filename:
            file = form.image.data  # store image into variable
            print(f"DEBUG: File received - Filename: {file.filename}")
            print(f"DEBUG: File content type: {file.content_type}")

            filename = secure_filename(file.filename)  # run the filename through werkzeug
            unique_filename = f"user_{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"  # adding metadata to file name
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)  # set the file path with the folder so the app knows where to store the file

            try:
                # uploads the file to the server
                file.save(file_path)
                image_path = f"upload/{unique_filename}"
                print(f"DEBUG: Image successfully saved to: {file_path}")
                print(f"DEBUG: image_path saved in DB will be: {image_path}")
            except Exception as e:
                print(f"ERROR saving image: {e}")
                flash(f'Failed to save image: {str(e)}', 'warning')
        else:
            print("DEBUG: No image file was uploaded or filename was empty")


        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO ProgressLogs (user_id, date, title, details, image_path) VALUES (?, ?, ?, ?, ?)",
                    (current_user.id, date_str, title, details, image_path)
                )
                conn.commit()

            flash('Progress log added successfully!', 'success')
            return redirect(url_for('add_progress'))

        except Exception as e:
            flash('An error occurred while saving your progress.', 'error')
            print(f"ERROR saving progress: {e}")
            import traceback
            traceback.print_exc()  # Print full traceback in console

    return render_template('addProgress.html', form=form, username=current_user.username)

@app.route('/buy_stock', methods=['POST', 'GET'])
@login_required
def buy_stock():
    ticker = request.form.get('ticker', '').strip().upper()
    shares = request.form.get('shares', type=int)

    if not ticker or not shares or shares <= 0:
        flash('Invalid ticker or number of shares.', 'error')
        return redirect(url_for('buy_stock'))

    # Get current price
    stock_data, _, error = get_stock_info(ticker)
    if error or not stock_data or not stock_data['current_price']:
        flash('Could not fetch current price. Please try again.', 'error')
        return redirect(url_for('buy_stock'))

    price_per_share = stock_data['current_price']
    total_cost = round(price_per_share * shares, 2)

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Get user's current cash balance
            cursor.execute("SELECT cash_balance FROM UserBalances WHERE user_id = ?", (current_user.id,))
            balance_row = cursor.fetchone()
            current_balance = balance_row['cash_balance'] if balance_row else 0.0

            if current_balance < total_cost:
                flash(f'Insufficient funds! You need ${total_cost:,.2f} but only have ${current_balance:,.2f}', 'error')
                return redirect(url_for('buy_stock'))

            # Update cash balance
            new_balance = round(current_balance - total_cost, 2)
            cursor.execute(
                "UPDATE UserBalances SET cash_balance = ? WHERE user_id = ?",
                (new_balance, current_user.id)
            )

            # Update or insert into Portfolio
            cursor.execute("""
                INSERT INTO Portfolio (user_id, ticker, shares, average_buy_price)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id, ticker) 
                DO UPDATE SET 
                    shares = shares + ?,
                    average_buy_price = ((average_buy_price * shares) + (? * ?)) / (shares + ?),
                    last_updated = CURRENT_TIMESTAMP
            """, (current_user.id, ticker, shares, price_per_share,
                  shares, price_per_share, shares, shares))

            # Record transaction
            cursor.execute("""
                INSERT INTO Transactions 
                (user_id, ticker, transaction_type, shares, price_per_share, total_amount)
                VALUES (?, ?, 'BUY', ?, ?, ?)
            """, (current_user.id, ticker, shares, price_per_share, total_cost))

            conn.commit()

        flash(f'Successfully bought {shares} shares of {ticker} for ${total_cost:,.2f}', 'success')
        return redirect(url_for('quote_stock', ticker=ticker))   # Stay on same ticker

    except Exception as e:
        flash('An error occurred while processing your purchase.', 'error')
        print(f"Buy error: {e}")
        return redirect(url_for('buy_stock'))

@app.route('/create_question', methods=['GET', 'POST'])
@login_required
def createQuestion():
    quiz_data = None
    # fetches the selected quiz and its details
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT title, numQuestions FROM Quizzes WHERE id = ?", (session['created_quiz_id'],))
        quiz_data = cursor.fetchone()
        conn.close()

    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()

        # finds the number of questions in the selected quiz
        cursor.execute("SELECT numQuestions FROM Quizzes WHERE id = ?", (session['created_quiz_id'],))
        quiz_data = cursor.fetchone()

        # creates a new question create field for the number of questions previously defined in the quiz
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
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT cash_balance FROM UserBalances WHERE user_id = ?", (current_user.id,))
            balance_row = cursor.fetchone()
            cash_balance = float(balance_row['cash_balance']) if balance_row else 0.0

            cursor.execute("""
                           SELECT ticker, shares, average_buy_price
                           FROM Portfolio
                           WHERE user_id = ?
                           ORDER BY ticker
                           """, (current_user.id,))
            holdings = cursor.fetchall()

        # First pass: Calculate market values and total portfolio value
        enhanced_holdings = []
        portfolio_value = 0.0
        total_unrealized_pnl = 0.0
        total_cost_basis = 0.0

        for holding in holdings:
            ticker = holding['ticker']
            shares = holding['shares']
            avg_buy_price = holding['average_buy_price']

            stock_data, _, error = get_stock_info(ticker)
            current_price = stock_data['current_price'] if stock_data and not error else None

            if current_price:
                market_value = round(shares * current_price, 2)
                unrealized_pnl = round((current_price - avg_buy_price) * shares, 2)
                cost_basis = round(avg_buy_price * shares, 2)

                portfolio_value += market_value
                total_unrealized_pnl += unrealized_pnl
                total_cost_basis += cost_basis

                enhanced_holdings.append({
                    'ticker': ticker,
                    'shares': shares,
                    'avg_buy_price': round(avg_buy_price, 2),
                    'current_price': round(current_price, 2),
                    'market_value': market_value,
                    'unrealized_pnl': unrealized_pnl,
                    'pnl_percent': round(((current_price - avg_buy_price) / avg_buy_price * 100),
                                         2) if avg_buy_price > 0 else 0,
                    'weight': 0  # placeholder
                })
            else:
                enhanced_holdings.append({
                    'ticker': ticker,
                    'shares': shares,
                    'avg_buy_price': round(avg_buy_price, 2),
                    'current_price': None,
                    'market_value': None,
                    'unrealized_pnl': None,
                    'pnl_percent': None,
                    'weight': 0
                })

        total_portfolio_value = round(cash_balance + portfolio_value, 2)
        overall_return = round(((portfolio_value - total_cost_basis) / total_cost_basis * 100),
                               2) if total_cost_basis > 0 else 0

        # Second pass: Calculate correct weights
        if portfolio_value > 0:
            for holding in enhanced_holdings:
                if holding['market_value']:
                    holding['weight'] = round((holding['market_value'] / portfolio_value) * 100, 1)

        # Prepare data for Plotly pie chart
        tickers_for_pie = [h['ticker'] for h in enhanced_holdings if h['market_value']]
        weights_for_pie = [h['weight'] for h in enhanced_holdings if h['market_value']]

        # Create Plotly Pie Chart
        # import plotly.express as px
        # import plotly.io as pio

        allocation_chart = ""
        if tickers_for_pie and weights_for_pie:
            fig = px.pie(
                names=tickers_for_pie,
                values=weights_for_pie,
                title="Asset Allocation by Market Value"
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(showlegend=False,
                              title_text=None,
                              margin=dict(l=0, r=10, t=30, b=0),
                              paper_bgcolor='rgba(0,0,0,0)',
                              plot_bgcolor='rgba(0,0,0,0)',
                              height=250,
                              width=250)
            allocation_chart = pio.to_html(fig, full_html=False, include_plotlyjs='cdn')

        # Top Gainer and Top Loser
        top_gainer = max(enhanced_holdings, key=lambda x: x.get('unrealized_pnl') or -999999, default=None)
        top_loser = min(enhanced_holdings, key=lambda x: x.get('unrealized_pnl') or 999999, default=None)
        print(top_gainer)
        print(top_loser)

        return render_template('dashboard.html',
                               cash_balance=round(cash_balance, 2),
                               portfolio_value=round(portfolio_value, 2),
                               total_portfolio_value=total_portfolio_value,
                               total_unrealized_pnl=round(total_unrealized_pnl, 2),
                               overall_return=overall_return,
                               total_invested=round(total_cost_basis, 2),
                               holdings=enhanced_holdings,
                               top_gainer=top_gainer,
                               top_loser=top_loser,
                               allocation_chart=allocation_chart)

    except Exception as e:
        print(f"Dashboard error: {e}")
        import traceback
        traceback.print_exc()
        flash('Error loading dashboard.', 'error')
        return render_template(
            'dashboard.html',
            cash_balance=0,
            portfolio_value=0,
            total_portfolio_value=0,
            total_unrealized_pnl=0,
            overall_return=0,
            total_invested=0,
            holdings=[],
            top_gainer=None,
            top_loser=None,
            allocation_chart=""
        )


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
    return redirect(url_for('login'))
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

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    logout_user()
    flash('You have successfully logged out, come back soon!', 'success')
    return redirect(url_for('login'))


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

@app.route('/quote_stock', methods=['GET', 'POST'])
@login_required
def quote_stock():
    form = QuoteForm()

    stock_data = None
    chart_data = None
    error = None
    tickerName = None

    if form.validate_on_submit():
        tickerName = request.form.get('tickerName', '').strip()

        if tickerName:
            stock_data, chart_data, error = get_stock_info(tickerName)
        else:
            error = "Please enter a stock ticker (e.g. AAPL)"

    return render_template('quoteStock.html', form=form, stock_data=stock_data, chart_data=chart_data, error=error,
                               tickerName=tickerName, username=current_user.username)

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

@app.route('/sell_stock', methods=['POST'])
@login_required
def sell_stock():
    ticker = request.form.get('ticker', '').strip().upper()
    shares_to_sell = request.form.get('shares', type=int)

    if not ticker or not shares_to_sell or shares_to_sell < 1:
        flash('Invalid ticker or number of shares.', 'error')
        return redirect(url_for('dashboard'))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Get current holding
            cursor.execute("""
                SELECT shares, average_buy_price 
                FROM Portfolio 
                WHERE user_id = ? AND ticker = ?
            """, (current_user.id, ticker))
            holding = cursor.fetchone()

            if not holding or holding['shares'] < shares_to_sell:
                flash(f'You only own {holding["shares"] if holding else 0} shares of {ticker}. Cannot sell {shares_to_sell} shares.', 'error')
                return redirect(url_for('dashboard'))

            avg_buy_price = holding['average_buy_price']

            # Get current market price
            stock_data, _, error = get_stock_info(ticker)
            if error or not stock_data or not stock_data.get('current_price'):
                flash('Could not fetch current price. Please try again later.', 'error')
                return redirect(url_for('dashboard'))

            current_price = stock_data['current_price']
            total_proceeds = round(current_price * shares_to_sell, 2)

            # Update cash balance
            cursor.execute("SELECT cash_balance FROM UserBalances WHERE user_id = ?", (current_user.id,))
            balance_row = cursor.fetchone()
            current_balance = float(balance_row['cash_balance']) if balance_row else 0.0
            new_balance = round(current_balance + total_proceeds, 2)

            cursor.execute(
                "UPDATE UserBalances SET cash_balance = ? WHERE user_id = ?",
                (new_balance, current_user.id)
            )

            # Update portfolio
            remaining_shares = holding['shares'] - shares_to_sell
            if remaining_shares > 0:
                cursor.execute("""
                    UPDATE Portfolio 
                    SET shares = ?, last_updated = CURRENT_TIMESTAMP 
                    WHERE user_id = ? AND ticker = ?
                """, (remaining_shares, current_user.id, ticker))
            else:
                cursor.execute("DELETE FROM Portfolio WHERE user_id = ? AND ticker = ?",
                             (current_user.id, ticker))

            # Record transaction
            cursor.execute("""
                INSERT INTO Transactions 
                (user_id, ticker, transaction_type, shares, price_per_share, total_amount)
                VALUES (?, ?, 'SELL', ?, ?, ?)
            """, (current_user.id, ticker, shares_to_sell, current_price, total_proceeds))

            conn.commit()

        flash(f'Successfully sold {shares_to_sell} shares of {ticker} for ${total_proceeds:,.2f}', 'success')

    except Exception as e:
        flash('An error occurred while selling the stock.', 'error')
        print(f"Sell error: {e}")
        import traceback
        traceback.print_exc()

    return redirect(url_for('dashboard'))

@app.route('/transactions')
@login_required
def transactions():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                           SELECT t.id,
                                  t.ticker,
                                  t.transaction_type,
                                  t.shares,
                                  t.price_per_share,
                                  t.total_amount,
                                  t.timestamp,
                                  t.user_id
                           FROM Transactions t
                           WHERE t.user_id = ?
                           ORDER BY t.timestamp DESC
                           """, (current_user.id,))

            transactions = cursor.fetchall()

        return render_template('transactions.html',
                               transactions=transactions,
                               username=current_user.username)

    except Exception as e:
        print(f"Transactions error: {e}")
        flash('Error loading transaction history.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/view_log', methods=['GET'])
@login_required
def view_log():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT date, title, details, image_path
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
