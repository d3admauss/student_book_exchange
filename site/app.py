from flask import Flask, render_template, redirect, url_for, flash, session, request, jsonify, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, validators, SelectField, DateField
from flask_bcrypt import Bcrypt
import psycopg2
import os
import datetime
import secrets
from werkzeug.utils import secure_filename
from flask_wtf.file import FileField, FileAllowed
from flask_socketio import SocketIO, emit, join_room, leave_room

# Define allowed extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
bcrypt = Bcrypt(app)

# Initialize SocketIO after creating the Flask app
socketio = SocketIO(app, cors_allowed_origins="*")

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database connection
conn = psycopg2.connect(
    host="localhost",
    database="student_library",
    user="postgres",
    password="yourpassword"
)

cursor = conn.cursor()

# Create necessary tables
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        university VARCHAR(100)
    )
""")

# Add university column to existing users table if it doesn't exist
cursor.execute("""
    DO $$ 
    BEGIN
        IF NOT EXISTS (
            SELECT 1 
            FROM information_schema.columns 
            WHERE table_name = 'users' 
            AND column_name = 'university'
        ) THEN
            ALTER TABLE users ADD COLUMN university VARCHAR(100);
        END IF;
    END $$;
""")

# Add email unique constraint if it doesn't exist
cursor.execute("""
    DO $$ 
    BEGIN
        IF NOT EXISTS (
            SELECT 1 
            FROM pg_constraint 
            WHERE conname = 'users_email_key'
        ) THEN
            ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
        END IF;
    END $$;
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS book_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS books (
        id SERIAL PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        author VARCHAR(100),
        description TEXT,
        owner_id INTEGER REFERENCES users(id),
        status VARCHAR(20) DEFAULT 'available',
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

cursor.execute("""
    ALTER TABLE books 
    ADD COLUMN IF NOT EXISTS category_id INTEGER REFERENCES book_categories(id),
    ADD COLUMN IF NOT EXISTS condition VARCHAR(50),
    ADD COLUMN IF NOT EXISTS return_date DATE,
    ADD COLUMN IF NOT EXISTS image_path VARCHAR(255)
""")

cursor.execute("""
    ALTER TABLE books 
    ADD COLUMN IF NOT EXISTS added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS exchanges (
        id SERIAL PRIMARY KEY,
        book_id INTEGER REFERENCES books(id),
        lender_id INTEGER REFERENCES users(id),
        borrower_id INTEGER REFERENCES users(id),
        start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_date TIMESTAMP,
        status VARCHAR(20) DEFAULT 'pending'
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS favorites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        book_id INTEGER REFERENCES books(id),
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, book_id)
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS reviews (
        id SERIAL PRIMARY KEY,
        book_id INTEGER REFERENCES books(id),
        reviewer_id INTEGER REFERENCES users(id),
        rating INTEGER CHECK (rating BETWEEN 1 AND 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender_id INTEGER REFERENCES users(id),
        receiver_id INTEGER REFERENCES users(id),
        book_id INTEGER REFERENCES books(id),
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_read BOOLEAN DEFAULT FALSE
    )
""")

# Добавляем столбец edited_at в таблицу messages, если его еще нет
cursor.execute("""
    DO $$ 
    BEGIN
        IF NOT EXISTS (
            SELECT 1 
            FROM information_schema.columns 
            WHERE table_name = 'messages' 
            AND column_name = 'edited_at'
        ) THEN
            ALTER TABLE messages ADD COLUMN edited_at TIMESTAMP;
        END IF;
    END $$;
""")

# Add this after your database connection setup
cursor.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 
            FROM information_schema.columns 
            WHERE table_name='users' AND column_name='profile_image'
        ) THEN
            ALTER TABLE users ADD COLUMN profile_image VARCHAR(255);
        END IF;
    END $$;
""")

# Add this after your other table alterations
cursor.execute("""
    DO $$ 
    BEGIN
        IF NOT EXISTS (
            SELECT 1 
            FROM information_schema.columns 
            WHERE table_name = 'users' 
            AND column_name = 'display_name'
        ) THEN
            ALTER TABLE users ADD COLUMN display_name VARCHAR(100);
        END IF;
    END $$;
""")

# Add these columns to your books table if they don't exist
cursor.execute("""
    ALTER TABLE books 
    DROP COLUMN IF EXISTS isbn;
""")

cursor.execute("""
    ALTER TABLE books 
    ADD COLUMN IF NOT EXISTS category_id INTEGER REFERENCES book_categories(id),
    ADD COLUMN IF NOT EXISTS condition VARCHAR(50),
    ADD COLUMN IF NOT EXISTS image_path VARCHAR(255),
    ADD COLUMN IF NOT EXISTS isbn VARCHAR(50),
    ADD COLUMN IF NOT EXISTS publisher VARCHAR(100),
    ADD COLUMN IF NOT EXISTS publication_year VARCHAR(50),
    ADD COLUMN IF NOT EXISTS loan_duration INTEGER DEFAULT 14
""")

# Add pdf_path column to books table if it doesn't exist
cursor.execute("""
    DO $$ 
    BEGIN
        IF NOT EXISTS (
            SELECT 1 
            FROM information_schema.columns 
            WHERE table_name = 'books' 
            AND column_name = 'pdf_path'
        ) THEN
            ALTER TABLE books ADD COLUMN pdf_path VARCHAR(255);
        END IF;
    END $$;
""")

# Update the publication_year column type
cursor.execute("""
    ALTER TABLE books 
    DROP COLUMN IF EXISTS publication_year;
""")

cursor.execute("""
    ALTER TABLE books 
    ADD COLUMN publication_year VARCHAR(50);
""")

# Create hidden_chats table for tracking hidden chats
cursor.execute("""
    CREATE TABLE IF NOT EXISTS hidden_chats (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        other_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        hidden_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, other_user_id)
    )
""")

# Add edited_at column to reviews table if it doesn't exist
cursor.execute("""
    DO $$ 
    BEGIN
        IF NOT EXISTS (
            SELECT 1 
            FROM information_schema.columns 
            WHERE table_name = 'reviews' 
            AND column_name = 'edited_at'
        ) THEN
            ALTER TABLE reviews ADD COLUMN edited_at TIMESTAMP;
        END IF;
    END $$;
""")

conn.commit()

# In-memory storage for user information (replace with a database in a real application)
users = {}

# Add new book status options
BOOK_STATUS = {
    'AVAILABLE': 'available',
    'BORROWED': 'borrowed',
    'PENDING': 'pending',
    'RESERVED': 'reserved'
}

# Add new exchange status options
EXCHANGE_STATUS = {
    'PENDING': 'pending',
    'ACCEPTED': 'accepted',
    'REJECTED': 'rejected',
    'COMPLETED': 'completed'
}

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        validators.DataRequired(),
        validators.Length(min=2, max=20, message="Username must be between 2 and 20 characters")
    ])
    password = PasswordField('Password', validators=[
        validators.DataRequired(),
        validators.Length(min=6, message="Password must be at least 6 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        validators.DataRequired(),
        validators.EqualTo('password', message='Passwords must match')
    ])
    email = StringField('Email', validators=[
        validators.DataRequired(),
        validators.Email(message="Please enter a valid email address")
    ])
    university = StringField('University', validators=[
        validators.DataRequired(),
        validators.Length(min=2, message="Please enter a valid university name")
    ])
    submit = SubmitField('Sign Up')


class SignInForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    submit = SubmitField('Sign In')


class BookForm(FlaskForm):
    title = StringField('Title', validators=[validators.DataRequired()])
    author = StringField('Author', validators=[validators.DataRequired()])
    description = TextAreaField('Description', validators=[validators.DataRequired()])
    category = SelectField('Category', coerce=int)
    condition = SelectField('Condition', choices=[
        ('new', 'New'),
        ('like_new', 'Like New'),
        ('good', 'Good'),
        ('fair', 'Fair'),
        ('poor', 'Poor')
    ])
    isbn = StringField('ISBN', validators=[
        validators.Optional(),
        validators.Length(max=50, message="ISBN must not exceed 50 characters")
    ])
    publisher = StringField('Publisher', validators=[validators.Optional()])
    publication_year = StringField('Publication Year', validators=[validators.Optional()])
    image = FileField('Book Cover Image', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    pdf_file = FileField('Book PDF File', validators=[
        validators.Optional(),
        FileAllowed(['pdf'], 'PDF files only!')
    ])
    submit = SubmitField('Add Book')


class AdvancedSearchForm(FlaskForm):
    query = StringField('Search Term')
    category = SelectField('Category', coerce=int, choices=[], validators=[validators.Optional()])
    author = StringField('Author')
    condition = SelectField('Minimum Condition', choices=[
        ('', 'Any'),
        ('poor', 'Poor or better'),
        ('fair', 'Fair or better'),
        ('good', 'Good or better'),
        ('like_new', 'Like New or better'),
        ('new', 'New only')
    ], validators=[validators.Optional()])
    available_only = SelectField('Availability', choices=[
        ('all', 'All Books'),
        ('available', 'Available Only')
    ])
    sort_by = SelectField('Sort By', choices=[
        ('recent', 'Most Recent'),
        ('title', 'Title (A-Z)'),
        ('author', 'Author (A-Z)'),
        ('rating', 'Highest Rated')
    ])
    submit = SubmitField('Search')


def user_exists(username, password):
    # Check if the user exists and the provided password is correct
    if username in users:
        hashed_password = users[username]['password']
        return bcrypt.check_password_hash(hashed_password, password)
    return False


def generate_token():
    return secrets.token_urlsafe(16)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('home'))
        
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Check if username already exists
            cursor.execute("SELECT id FROM users WHERE username = %s", (form.username.data,))
            if cursor.fetchone():
                flash('Username already exists', 'error')
                return render_template('register.html', form=form)
            
            # Check if email already exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (form.email.data,))
            if cursor.fetchone():
                flash('Email already registered', 'error')
                return render_template('register.html', form=form)
                
            # Hash the password
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            # Insert new user
            cursor.execute("""
                INSERT INTO users (username, password, email, university)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (form.username.data, hashed_password, form.email.data, form.university.data))
            
            user_id = cursor.fetchone()[0]
            conn.commit()
            
            # Log the user in
            session['user_id'] = user_id
            session['username'] = form.username.data
            
            flash('Registration successful! Welcome to Student Book Exchange!', 'success')
            return redirect(url_for('home'))
            
        except Exception as e:
            conn.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            app.logger.error(f"Registration error: {str(e)}")
            
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('home'))

    form = SignInForm()
    if form.validate_on_submit():
        cursor.execute("""
            SELECT id, username, password 
            FROM users 
            WHERE username = %s
        """, (form.username.data,))
        
        user = cursor.fetchone()
        
        if user and bcrypt.check_password_hash(user[2], form.password.data):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('You have successfully logged in!', 'success')
            
            # Проверяем, было ли сохранено место перенаправления
            next_page = session.pop('next', None)
            if next_page:
                return redirect(next_page)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
            
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))


@app.route('/product/<int:product_id>')
def product(product_id):
    product_details = get_product_details(product_id)
    if not product_details:
        flash('Product not found!', 'error')
        return redirect(url_for('home'))

    return render_template('product.html', product_details=product_details)


def get_product_details(product_id):
    product_data = {
        2: {'name': 'Product 2', 'description': 'Description of Product 2.', 'price': 29.99},
        3: {'name': 'Product 3', 'description': 'Description of Product 3.', 'price': 29.99},
    }

    return product_data.get(product_id)


@app.route('/add_to_favorites/<int:product_id>', methods=['POST'])
def add_to_favorites(product_id):
    if 'user_id' not in session:
        flash('You need to sign in to add to favorites.', 'info')
        # Сохраняем URL для возврата после логина
        session['next'] = request.referrer
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    
    # Check if book exists
    cursor.execute("SELECT 1 FROM books WHERE id = %s", (product_id,))
    if not cursor.fetchone():
        flash('Book not found!', 'error')
        return redirect(url_for('home'))
    
    # Check if already in favorites
    cursor.execute(
        "SELECT 1 FROM favorites WHERE user_id = %s AND book_id = %s",
        (user_id, product_id)
    )
    
    if cursor.fetchone():
        # Already a favorite, remove it
        cursor.execute(
            "DELETE FROM favorites WHERE user_id = %s AND book_id = %s",
            (user_id, product_id)
        )
        conn.commit()
        flash('Book removed from favorites!', 'success')
    else:
        # Add to favorites
        cursor.execute(
            "INSERT INTO favorites (user_id, book_id) VALUES (%s, %s)",
            (user_id, product_id)
        )
        conn.commit()
        flash('Book added to favorites!', 'success')
    
    # Redirect back to the referring page or to favorites
    referrer = request.referrer
    if referrer and referrer != request.url:
        return redirect(referrer)
    else:
        return redirect(url_for('favorites'))


@app.route('/toggle_favorite/<int:book_id>', methods=['POST'])
def toggle_favorite(book_id):
    if 'user_id' not in session:
        # Сохраняем URL для возврата после логина
        if request.referrer:
            session['next'] = request.referrer
        return jsonify({'status': 'error', 'message': 'Please sign in first'}), 401
        
    user_id = session['user_id']
    
    # Check if book exists
    cursor.execute("SELECT 1 FROM books WHERE id = %s", (book_id,))
    if not cursor.fetchone():
        return jsonify({'status': 'error', 'message': 'Book not found'}), 404
    
    # Check if already in favorites
    cursor.execute(
        "SELECT 1 FROM favorites WHERE user_id = %s AND book_id = %s",
        (user_id, book_id)
    )
    
    if cursor.fetchone():
        # Already a favorite, remove it
        cursor.execute(
            "DELETE FROM favorites WHERE user_id = %s AND book_id = %s",
            (user_id, book_id)
        )
        conn.commit()
        return jsonify({'status': 'removed'})
    else:
        # Add to favorites
        cursor.execute(
            "INSERT INTO favorites (user_id, book_id) VALUES (%s, %s)",
            (user_id, book_id)
        )
        conn.commit()
        return jsonify({'status': 'added'})


@app.route('/check_favorites', methods=['POST'])
def check_favorites():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
        
    user_id = session['user_id']
    
    # Получить список ID книг для проверки из запроса
    data = request.get_json()
    if not data or 'book_ids' not in data:
        return jsonify({'status': 'error', 'message': 'No book IDs provided'}), 400
    
    book_ids = data['book_ids']
    if not book_ids:
        return jsonify({'favorites': []})
    
    # Преобразуем строковые ID в целые числа
    book_ids = [int(id) for id in book_ids]
    
    # Получаем список избранных книг пользователя из предоставленного списка
    placeholders = ', '.join(['%s'] * len(book_ids))
    query = f"""
        SELECT book_id FROM favorites 
        WHERE user_id = %s AND book_id IN ({placeholders})
    """
    
    params = [user_id] + book_ids
    try:
        cursor.execute(query, params)
        favorite_books = [row[0] for row in cursor.fetchall()]
    except psycopg2.ProgrammingError:
        # Обработка ситуации, когда нет результатов
        favorite_books = []
    
    return jsonify({'favorites': favorite_books})


@app.route('/remove_from_favorites/<int:book_id>', methods=['POST'])
def remove_from_favorites(book_id):
    if 'user_id' not in session:
        flash('You need to sign in to manage favorites.', 'info')
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    
    cursor.execute(
        "DELETE FROM favorites WHERE user_id = %s AND book_id = %s",
        (user_id, book_id)
    )
    conn.commit()
    
    flash('Book removed from favorites!', 'success')
    
    # Redirect back to the referring page or to favorites
    referrer = request.referrer
    if referrer and referrer != request.url:
        return redirect(referrer)
    else:
        return redirect(url_for('favorites'))


@app.route('/perform_logout', methods=['POST'])
def perform_logout():
    choice = request.form.get('choice', 'yes')

    if choice == 'yes':
        # Clear session data if the user clicked on "Yes, Logout"
        session.pop('username', None)
        flash('You have been logged out successfully!', 'success')
    else:
        flash('Logout canceled. You are still signed in.', 'info')

    return redirect(url_for('home'))


@app.route('/account')
def account():
    if 'user_id' not in session:
        flash('Please sign in to access your account', 'error')
        return redirect(url_for('login'))

    # Fetch user data from the database
    cursor.execute("""
        SELECT username, email, display_name 
        FROM users 
        WHERE id = %s
    """, (session['user_id'],))
    user = cursor.fetchone()
    
    if user:
        username, email, display_name = user
        # Use display_name if it exists, otherwise use username
        display_name = display_name or username
    else:
        flash('User not found', 'error')
        return redirect(url_for('login'))

    return render_template('account.html', 
                         username=username, 
                         email=email, 
                         display_name=display_name)


@app.route('/')
def home():
    # Get sorting parameter from request
    sort_by = request.args.get('sort', 'recent')
    
    try:
        # Build the query based on sort parameter
        base_query = """
            SELECT b.*, u.username as owner_name, 
                   COALESCE(u.display_name, u.username) as owner_display_name,
                   c.name as category_name,
                   COALESCE(AVG(r.rating), 0) as avg_rating, 
                   COUNT(r.id) as review_count
            FROM books b
            JOIN users u ON b.owner_id = u.id
            LEFT JOIN book_categories c ON b.category_id = c.id
            LEFT JOIN reviews r ON b.id = r.book_id
            WHERE b.status = 'available'
            GROUP BY b.id, u.username, u.display_name, c.name
        """
        
        # Add the appropriate ORDER BY clause
        if sort_by == 'rating':
            order_clause = "ORDER BY avg_rating DESC, review_count DESC, b.added_date DESC"
        elif sort_by == 'popular':
            order_clause = "ORDER BY review_count DESC, b.added_date DESC"
        else:  # default: recent
            order_clause = "ORDER BY COALESCE(b.added_date, NOW()) DESC"
            
        full_query = f"{base_query} {order_clause}"
        
        cursor.execute(full_query)
    except psycopg2.Error:
        # If that fails, use a simpler query without complex ordering
        cursor.execute("""
            SELECT b.*, u.username as owner_name, 
                   COALESCE(u.display_name, u.username) as owner_display_name,
                   c.name as category_name,
                   COALESCE(AVG(r.rating), 0) as avg_rating, 
                   COUNT(r.id) as review_count
            FROM books b
            JOIN users u ON b.owner_id = u.id
            LEFT JOIN book_categories c ON b.category_id = c.id
            LEFT JOIN reviews r ON b.id = r.book_id
            WHERE b.status = 'available'
            GROUP BY b.id, u.username, u.display_name, c.name
        """)
    
    books_tuples = cursor.fetchall()
    
    # Convert tuples to dictionaries for better template access
    column_names = [desc[0] for desc in cursor.description]
    books = []
    for book_tuple in books_tuples:
        book_dict = dict(zip(column_names, book_tuple))
        books.append(book_dict)

    # Get categories with book counts - convert to dictionaries for easier access
    cursor.execute("""
        SELECT c.id, c.name, COUNT(b.id) as book_count
        FROM book_categories c
        LEFT JOIN books b ON c.id = b.category_id AND b.status = 'available'
        GROUP BY c.id, c.name
        ORDER BY book_count DESC
    """)
    category_tuples = cursor.fetchall()
    
    # Convert tuples to dictionaries for easier access in the template
    categories = []
    for cat in category_tuples:
        categories.append({
            'id': cat[0],
            'name': cat[1],
            'book_count': cat[2]
        })

    return render_template('home.html', books=books, categories=categories, current_sort=sort_by)


@app.route('/register')
def root():
    return redirect(url_for('register.html'))


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    category_id = request.args.get('category', '0')
    sort_by = request.args.get('sort_by', 'recent')
    available_only = request.args.get('available_only', 'available')
    
    # If query is empty, redirect back to the referring page or to home page
    if not query:
        referrer = request.referrer
        if referrer and referrer != request.url:
            return redirect(referrer)
        else:
            return redirect(url_for('home'))
    
    # Get all categories for the filter dropdown
    cursor.execute("SELECT id, name FROM book_categories ORDER BY name")
    categories = cursor.fetchall()
    
    # Build the query based on filters
    sql_query = """
        SELECT b.*, u.username as owner_name,
               COALESCE(u.display_name, u.username) as owner_display_name,
               c.name as category_name,
               COALESCE(AVG(r.rating), 0) as avg_rating,
               COUNT(r.id) as review_count
        FROM books b
        LEFT JOIN users u ON b.owner_id = u.id
        LEFT JOIN book_categories c ON b.category_id = c.id
        LEFT JOIN reviews r ON b.id = r.book_id
    """
    
    conditions = []
    params = []
    
    if query:
        conditions.append("(LOWER(b.title) LIKE LOWER(%s) OR LOWER(b.author) LIKE LOWER(%s))")
        params.extend([f'%{query}%', f'%{query}%'])
    
    if category_id and category_id != '0':
        conditions.append("b.category_id = %s")
        params.append(category_id)
    
    if available_only == 'available':
        conditions.append("b.status = 'available'")
    
    if conditions:
        sql_query += " WHERE " + " AND ".join(conditions)
    
    sql_query += " GROUP BY b.id, u.username, u.display_name, c.name"
    
    # Add sorting
    if sort_by == 'title':
        sql_query += " ORDER BY b.title ASC"
    elif sort_by == 'author':
        sql_query += " ORDER BY b.author ASC"
    elif sort_by == 'rating':
        sql_query += " ORDER BY avg_rating DESC"
    else:  # Default: recent
        sql_query += " ORDER BY b.added_date DESC"
    
    cursor.execute(sql_query, params)
    books_tuples = cursor.fetchall()

    # Convert tuples to dictionaries for better template access
    column_names = [desc[0] for desc in cursor.description]
    books = []
    for book_tuple in books_tuples:
        book_dict = dict(zip(column_names, book_tuple))
        books.append(book_dict)

    # Get favorite books for the user if logged in
    favorite_books_ids = []
    if 'user_id' in session:
        cursor.execute(
            "SELECT book_id FROM favorites WHERE user_id = %s",
            (session['user_id'],)
        )
        favorite_books_ids = [row[0] for row in cursor.fetchall()]
    
    return render_template('search_results.html', 
                          books=books, 
                          query=query, 
                          categories=categories,
                          favorite_books_ids=favorite_books_ids)


@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if 'user_id' not in session:
        flash('Please sign in to add books', 'error')
        return redirect(url_for('login'))

    form = BookForm()
    
    # Get categories for the dropdown
    cursor.execute("SELECT id, name FROM book_categories ORDER BY name")
    categories = cursor.fetchall()
    form.category.choices = [(c[0], c[1]) for c in categories]

    # Get user's display name
    cursor.execute("SELECT display_name, username FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    display_name = user[0] if user[0] else user[1]  # Use display_name if available, otherwise fall back to username
    
    # Set publisher to current user's display name
    form.publisher.data = display_name

    if form.validate_on_submit():
        # Handle image upload
        image_path = None
        if form.image.data:
            image = form.image.data
            filename = secure_filename(f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}")
            image_path = f"uploads/{filename}"
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Handle PDF upload
        pdf_path = None
        if form.pdf_file.data:
            pdf = form.pdf_file.data
            pdf_filename = secure_filename(f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{pdf.filename}")
            pdf_path = f"uploads/{pdf_filename}"
            # Ensure the uploads folder exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            pdf.save(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename))

        # Use a default loan_duration of 14 days
        loan_duration = 14
        
        # Insert book into database without the loan_duration field
        cursor.execute("""
            INSERT INTO books (
                title, author, description, owner_id, category_id, 
                condition, image_path, isbn, publisher, publication_year,
                loan_duration, pdf_path
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            form.title.data, 
            form.author.data, 
            form.description.data, 
            session['user_id'],
            form.category.data,
            form.condition.data,
            image_path,
            form.isbn.data,
            display_name,  # Use display_name instead of username
            form.publication_year.data,
            loan_duration,  # Use default loan_duration
            pdf_path
        ))
        conn.commit()
        
        flash('Book added successfully!', 'success')
        return redirect(url_for('my_books'))

    return render_template('add_book.html', form=form)


@app.route('/book/<int:book_id>')
def book_detail(book_id):
    # Get book details
    cursor.execute("""
        SELECT b.*, u.username as owner_name, u.email as owner_email,
               COALESCE(u.display_name, u.username) as owner_display_name,
               c.name as category_name,
               COALESCE(AVG(r.rating), 0) as avg_rating, 
               COUNT(r.id) as review_count,
               b.loan_duration, b.pdf_path, u.username as owner_username
        FROM books b
        JOIN users u ON b.owner_id = u.id
        LEFT JOIN book_categories c ON b.category_id = c.id
        LEFT JOIN reviews r ON b.id = r.book_id
        WHERE b.id = %s
        GROUP BY b.id, u.username, u.email, u.display_name, c.name, b.loan_duration, b.pdf_path, u.username
    """, (book_id,))
    
    book_tuple = cursor.fetchone()
    
    if not book_tuple:
        flash('Book not found', 'error')
        return redirect(url_for('home'))
    
    # Convert tuple to dictionary for better template access
    column_names = [desc[0] for desc in cursor.description]
    book = dict(zip(column_names, book_tuple))
    
    # Get reviews for this book
    cursor.execute("""
        SELECT r.id, r.reviewer_id, u.username as reviewer_name, 
               r.rating, r.comment, r.created_at, r.edited_at,
               COALESCE(u.display_name, u.username) as reviewer_display_name
        FROM reviews r
        JOIN users u ON r.reviewer_id = u.id
        WHERE r.book_id = %s
        ORDER BY r.created_at DESC
    """, (book_id,))
    
    reviews = []
    for review in cursor.fetchall():
        # Format dates properly before sending to template with the requested format
        created_at = review[5]
        if created_at:
            created_at = created_at.strftime('%d/%m/%y %H:%M:%S')
            
        edited_at = review[6]
        if edited_at:
            edited_at = True  # Just need a boolean for the edit tag
            
        reviews.append({
            'id': review[0],
            'reviewer_id': review[1],
            'reviewer_name': review[2],
            'rating': review[3],
            'comment': review[4],
            'created_at': created_at,
            'edited_at': edited_at,
            'reviewer_display_name': review[7]
        })
    
    # Check if the book is in the user's favorites
    is_favorite = False
    if 'user_id' in session:
        cursor.execute(
            "SELECT 1 FROM favorites WHERE user_id = %s AND book_id = %s",
            (session['user_id'], book_id)
        )
        is_favorite = cursor.fetchone() is not None
    
    return render_template('book_detail.html', 
                          book=book, 
                          reviews=reviews, 
                          is_favorite=is_favorite)


@app.route('/add_review/<int:book_id>', methods=['POST'])
def add_review(book_id):
    app.logger.info(f"Add review request for book_id: {book_id}")
    app.logger.info(f"Headers: {request.headers}")
    app.logger.info(f"Form data: {request.form}")
    
    if 'user_id' not in session:
        app.logger.warning("No user_id in session")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'Please sign in to review books'})
        flash('Please sign in to review books', 'error')
        return redirect(url_for('login'))
    
    reviewer_id = session['user_id']
    app.logger.info(f"Reviewer ID: {reviewer_id}")
    
    # Check if the book exists
    cursor.execute("SELECT owner_id FROM books WHERE id = %s", (book_id,))
    book = cursor.fetchone()
    
    if not book:
        app.logger.warning(f"Book not found: {book_id}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'Book not found'})
        flash('Book not found', 'error')
        return redirect(url_for('home'))
    
    # Check if the user is not the owner of the book
    if book[0] == reviewer_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'You cannot review your own book'})
        flash('You cannot review your own book', 'error')
        return redirect(url_for('book_detail', book_id=book_id))
    
    # We allow multiple reviews from the same user
    rating = request.form.get('rating')
    comment = request.form.get('comment')
    
    if not rating or not comment:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'Rating and comment are required'})
        flash('Rating and comment are required', 'error')
        return redirect(url_for('book_detail', book_id=book_id))
    
    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise ValueError('Rating must be between 1 and 5')
        
        # Add new review
        cursor.execute("""
            INSERT INTO reviews (book_id, reviewer_id, rating, comment)
            VALUES (%s, %s, %s, %s)
        """, (book_id, reviewer_id, rating, comment))
        message = 'Your review has been added'
        
        conn.commit()
        
        # Get updated reviews for the book - include edited_at in the query
        cursor.execute("""
            SELECT r.id, r.reviewer_id, u.username as reviewer_name, 
                   r.rating, r.comment, r.created_at, r.edited_at,
                   COALESCE(u.display_name, u.username) as reviewer_display_name
            FROM reviews r
            JOIN users u ON r.reviewer_id = u.id
            WHERE r.book_id = %s
            ORDER BY r.created_at DESC
        """, (book_id,))
        
        reviews = []
        for review in cursor.fetchall():
            reviews.append({
                'id': review[0],
                'reviewer_id': review[1],
                'reviewer_name': review[2],
                'rating': review[3],
                'comment': review[4],
                'created_at': review[5].strftime('%d/%m/%y %H:%M:%S') if review[5] else None,
                'edited_at': review[6].isoformat() if review[6] else None,
                'reviewer_display_name': review[7]
            })
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            response = jsonify({
                'status': 'success',
                'message': message,
                'reviews': reviews
            })
            response.headers['Content-Type'] = 'application/json'
            return response
            
        flash(message, 'success')
        
    except ValueError as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            response = jsonify({'status': 'error', 'message': str(e)})
            response.headers['Content-Type'] = 'application/json'
            return response
        flash(str(e), 'error')
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error adding review: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            response = jsonify({'status': 'error', 'message': 'An error occurred while submitting your review'})
            response.headers['Content-Type'] = 'application/json'
            return response
        flash('An error occurred while submitting your review', 'error')
    
    return redirect(url_for('book_detail', book_id=book_id))


@app.route('/edit_review/<int:review_id>', methods=['POST'])
def edit_review(review_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'Please sign in to edit reviews'})
        flash('Please sign in to edit reviews', 'error')
        return redirect(url_for('login'))
    
    reviewer_id = session['user_id']
    
    try:
        # Get the current review data first
        cursor.execute("""
            SELECT r.id, r.book_id, r.reviewer_id, r.edited_at
            FROM reviews r
            WHERE r.id = %s
        """, (review_id,))
        
        review = cursor.fetchone()
        
        if not review:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': 'Review not found'})
            flash('Review not found', 'error')
            return redirect(url_for('home'))
        
        if review[2] != reviewer_id:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': 'You can only edit your own reviews'})
            flash('You can only edit your own reviews', 'error')
            return redirect(url_for('book_detail', book_id=review[1]))
        
        rating = request.form.get('rating')
        comment = request.form.get('comment')
        
        if not rating or not comment:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': 'Rating and comment are required'})
            flash('Rating and comment are required', 'error')
            return redirect(url_for('book_detail', book_id=review[1]))
        
        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                raise ValueError('Rating must be between 1 and 5')
            
            # Update review and set edited_at timestamp
            cursor.execute("""
                UPDATE reviews
                SET rating = %s, comment = %s, edited_at = CURRENT_TIMESTAMP
                WHERE id = %s AND reviewer_id = %s
                RETURNING edited_at
            """, (rating, comment, review_id, reviewer_id))
            
            edited_at = cursor.fetchone()[0]
            conn.commit()
            
            # Get updated reviews with proper edited_at handling
            cursor.execute("""
                SELECT r.id, r.reviewer_id, u.username as reviewer_name, 
                       r.rating, r.comment, r.created_at, r.edited_at,
                       COALESCE(u.display_name, u.username) as reviewer_display_name
                FROM reviews r
                JOIN users u ON r.reviewer_id = u.id
                WHERE r.book_id = %s
                ORDER BY r.created_at DESC
            """, (review[1],))
            
            reviews = []
            for review_data in cursor.fetchall():
                reviews.append({
                    'id': review_data[0],
                    'reviewer_id': review_data[1],
                    'reviewer_name': review_data[2],
                    'rating': review_data[3],
                    'comment': review_data[4],
                    'created_at': review_data[5].strftime('%d/%m/%y %H:%M:%S') if review_data[5] else None,
                    'edited_at': review_data[6].isoformat() if review_data[6] else None,
                    'reviewer_display_name': review_data[7]
                })
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'status': 'success',
                    'message': 'Your review has been updated',
                    'reviews': reviews
                })
            
            flash('Your review has been updated', 'success')
            
        except ValueError as e:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'message': str(e)})
            flash(str(e), 'error')
            
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error editing review: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'An error occurred while editing your review'})
        flash('An error occurred while editing your review', 'error')
    
    return redirect(url_for('book_detail', book_id=review[1]))


@app.route('/delete_review/<int:review_id>', methods=['POST'])
def delete_review(review_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'Please sign in to delete reviews'})
        flash('Please sign in to delete reviews', 'error')
        return redirect(url_for('login'))
    
    reviewer_id = session['user_id']
    
    # Check if review exists and belongs to user
    cursor.execute("""
        SELECT r.id, r.book_id, r.reviewer_id
        FROM reviews r
        WHERE r.id = %s
    """, (review_id,))
    
    review = cursor.fetchone()
    
    if not review:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'Review not found'})
        flash('Review not found', 'error')
        return redirect(url_for('home'))
    
    if review[2] != reviewer_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'message': 'You can only delete your own reviews'})
        flash('You can only delete your own reviews', 'error')
        return redirect(url_for('book_detail', book_id=review[1]))
    
    try:
        # Delete review
        cursor.execute("""
            DELETE FROM reviews
            WHERE id = %s AND reviewer_id = %s
        """, (review_id, reviewer_id))
        
        conn.commit()
        message = 'Your review has been deleted'
        
        # Get updated reviews for the book - include edited_at field
        cursor.execute("""
            SELECT r.id, r.reviewer_id, u.username as reviewer_name, 
                   r.rating, r.comment, r.created_at, r.edited_at,
                   COALESCE(u.display_name, u.username) as reviewer_display_name
            FROM reviews r
            JOIN users u ON r.reviewer_id = u.id
            WHERE r.book_id = %s
            ORDER BY r.created_at DESC
        """, (review[1],))
        
        reviews = []
        for review_data in cursor.fetchall():
            reviews.append({
                'id': review_data[0],
                'reviewer_id': review_data[1],
                'reviewer_name': review_data[2],
                'rating': review_data[3],
                'comment': review_data[4],
                'created_at': review_data[5].strftime('%d/%m/%y %H:%M:%S') if review_data[5] else None,
                'edited_at': review_data[6].isoformat() if review_data[6] else None,
                'reviewer_display_name': review_data[7]
            })
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            response = jsonify({
                'status': 'success',
                'message': message,
                'reviews': reviews
            })
            response.headers['Content-Type'] = 'application/json'
            return response
            
        flash(message, 'success')
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error deleting review: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            response = jsonify({'status': 'error', 'message': 'An error occurred while deleting your review'})
            response.headers['Content-Type'] = 'application/json'
            return response
        flash('An error occurred while deleting your review', 'error')
    
    return redirect(url_for('book_detail', book_id=review[1]))


@app.route('/my_books')
def my_books():
    if 'user_id' not in session:
        flash('Please sign in to view your books', 'error')
        return redirect(url_for('login'))
    
    cursor.execute("""
        SELECT b.*, c.name as category_name, u.username as owner_name,
               COALESCE(u.display_name, u.username) as owner_display_name,
               COALESCE(AVG(r.rating), 0) as avg_rating,
               COUNT(r.id) as review_count
        FROM books b
        LEFT JOIN book_categories c ON b.category_id = c.id
        LEFT JOIN users u ON b.owner_id = u.id
        LEFT JOIN reviews r ON b.id = r.book_id
        WHERE b.owner_id = %s
        GROUP BY b.id, c.name, u.username, u.display_name
        ORDER BY b.added_date DESC
    """, (session['user_id'],))
    
    books_tuples = cursor.fetchall()
    
    # Convert tuples to dictionaries for better template access
    column_names = [desc[0] for desc in cursor.description]
    books = []
    for book_tuple in books_tuples:
        book_dict = dict(zip(column_names, book_tuple))
        books.append(book_dict)
    
    return render_template('my_books.html', books=books)


def get_user_books(user_id):
    cursor.execute("""
        SELECT * FROM books WHERE owner_id = %s
    """, (user_id,))
    return cursor.fetchall()


def get_available_books():
    cursor.execute("""
        SELECT b.*, u.username as owner_name,
               COALESCE(AVG(r.rating), 0) as avg_rating,
               COUNT(r.id) as review_count
        FROM books b 
        JOIN users u ON b.owner_id = u.id 
        LEFT JOIN reviews r ON b.id = r.book_id
        GROUP BY b.id, u.username
        ORDER BY b.created_at DESC
    """)
    return cursor.fetchall()


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/how_it_works')
def how_it_works():
    return render_template('how_it_works.html')

@app.route('/category/<int:id>')
def category(id):
    # Get sorting parameter from request
    sort_by = request.args.get('sort', 'recent')
    
    # Build the base query
    base_query = """
        SELECT b.*, 
               u.username as owner_name,
               COALESCE(u.display_name, u.username) as owner_display_name,
               c.name as category_name,
               COALESCE(AVG(r.rating), 0) as avg_rating,
               COUNT(r.id) as review_count
        FROM books b
        JOIN users u ON b.owner_id = u.id
        LEFT JOIN book_categories c ON b.category_id = c.id
        LEFT JOIN reviews r ON b.id = r.book_id
        WHERE b.category_id = %s AND b.status = 'available'
        GROUP BY b.id, u.username, u.display_name, c.name
    """
    
    # Add the appropriate ORDER BY clause
    if sort_by == 'rating':
        order_clause = "ORDER BY avg_rating DESC, review_count DESC, b.added_date DESC"
    elif sort_by == 'popular':
        order_clause = "ORDER BY review_count DESC, b.added_date DESC"
    else:  # default: recent
        order_clause = "ORDER BY COALESCE(b.added_date, NOW()) DESC"
        
    full_query = f"{base_query} {order_clause}"
    
    cursor.execute(full_query, (id,))
    
    books_tuples = cursor.fetchall()
    
    # Convert tuples to dictionaries for better template access
    column_names = [desc[0] for desc in cursor.description]
    books = []
    for book_tuple in books_tuples:
        book_dict = dict(zip(column_names, book_tuple))
        books.append(book_dict)
    
    # Get all categories for the search form
    cursor.execute("""
        SELECT c.id, c.name, COUNT(b.id) as book_count
        FROM book_categories c
        LEFT JOIN books b ON c.id = b.category_id AND b.status = 'available'
        GROUP BY c.id, c.name
        ORDER BY book_count DESC
    """)
    category_tuples = cursor.fetchall()
    
    # Convert tuples to dictionaries for easier access in the template
    categories = []
    for cat in category_tuples:
        categories.append({
            'id': cat[0],
            'name': cat[1],
            'book_count': cat[2]
        })
    
    cursor.execute("SELECT name FROM book_categories WHERE id = %s", (id,))
    category_name = cursor.fetchone()[0]
    
    return render_template('category.html', 
                           books=books, 
                           category_name=category_name, 
                           categories=categories, 
                           current_sort=sort_by)

# Add this function to initialize categories
def initialize_categories():
    # Check if we have categories, if not add some default ones
    cursor.execute("SELECT COUNT(*) FROM book_categories")
    count = cursor.fetchone()[0]
    
    if count == 0:
        default_categories = [
            "Fiction", "Non-Fiction", "Science", "Mathematics", 
            "Computer Science", "Engineering", "Business", "Economics",
            "History", "Philosophy", "Psychology", "Biology",
            "Chemistry", "Physics", "Literature", "Language",
            "Art", "Music", "Health", "Medicine"
        ]
        
        for category in default_categories:
            cursor.execute(
                "INSERT INTO book_categories (name) VALUES (%s) ON CONFLICT (name) DO NOTHING",
                (category,)
            )
        conn.commit()

# Call this after creating tables
initialize_categories()

@app.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
def edit_book(book_id):
    if 'user_id' not in session:
        flash('Please sign in to edit books', 'error')
        return redirect(url_for('login'))
    
    # Log the incoming request for debugging
    app.logger.info(f"Edit book request for book_id: {book_id}")
    
    try:
        # Get the book details
        cursor.execute("""
            SELECT * FROM books WHERE id = %s AND owner_id = %s
        """, (book_id, session['user_id']))
        book_tuple = cursor.fetchone()
        
        if not book_tuple:
            flash('Book not found or you do not have permission to edit it', 'error')
            return redirect(url_for('my_books'))
        
        # Convert tuple to dictionary for better template access
        column_names = [desc[0] for desc in cursor.description]
        book = dict(zip(column_names, book_tuple))
        
        form = BookForm()
        
        # Get categories for the dropdown
        cursor.execute("SELECT id, name FROM book_categories ORDER BY name")
        categories = cursor.fetchall()
        form.category.choices = [(c[0], c[1]) for c in categories]
        
        # Get user's display name
        cursor.execute("SELECT display_name, username FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        display_name = user[0] if user[0] else user[1]  # Use display_name if available, otherwise fall back to username
        
        if request.method == 'POST':
            if form.validate_on_submit():
                try:
                    # Handle image upload
                    image_path = book['image_path']  # Keep existing image path by default
                    if form.image.data:
                        # Delete old image if it exists
                        if image_path:
                            old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_path.split('/')[-1])
                            if os.path.exists(old_image_path):
                                os.remove(old_image_path)
                        
                        # Save new image
                        image = form.image.data
                        filename = secure_filename(f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}")
                        image_path = f"uploads/{filename}"
                        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    
                    # Handle PDF upload
                    pdf_path = book['pdf_path']
                    if form.pdf_file.data:
                        # Delete old PDF if it exists
                        if pdf_path:
                            old_pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_path.split('/')[-1])
                            if os.path.exists(old_pdf_path):
                                try:
                                    os.remove(old_pdf_path)
                                    app.logger.info(f"Deleted old PDF file: {old_pdf_path}")
                                except Exception as e:
                                    app.logger.error(f"Error deleting old PDF file: {e}")

                        # Save new PDF
                        pdf = form.pdf_file.data
                        pdf_filename = secure_filename(f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{pdf.filename}")
                        pdf_path = f"uploads/{pdf_filename}"
                        # Ensure the uploads folder exists
                        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                        pdf.save(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename))
                        app.logger.info(f"Saved new PDF file: {pdf_path}")
                    
                    # Use default loan_duration of 14 days
                    loan_duration = 14
                    
                    # Update book in database - removed loan_duration from form
                    cursor.execute("""
                        UPDATE books 
                        SET title = %s, author = %s, description = %s, category_id = %s,
                            condition = %s, image_path = %s, isbn = %s, publisher = %s,
                            publication_year = %s, loan_duration = %s, pdf_path = %s
                        WHERE id = %s AND owner_id = %s
                    """, (
                        form.title.data,
                        form.author.data,
                        form.description.data,
                        form.category.data,
                        form.condition.data,
                        image_path,
                        form.isbn.data,
                        display_name,  # Use display_name instead of username
                        form.publication_year.data,
                        loan_duration,  # Use fixed loan_duration
                        pdf_path,
                        book_id,
                        session['user_id']
                    ))
                    conn.commit()
                    
                    flash('Book updated successfully!', 'success')
                    return redirect(url_for('book_detail', book_id=book_id))
                    
                except Exception as e:
                    conn.rollback()
                    flash(f'An error occurred while updating the book: {str(e)}', 'error')
                    app.logger.error(f"Error updating book: {str(e)}")
            else:
                # If validation fails, show the errors
                for field, errors in form.errors.items():
                    for error in errors:
                        flash(f'Error in {field}: {error}', 'error')
                return render_template('edit_book.html', form=form, book=book)
        else:
            # Pre-populate form with existing data for GET request
            form.title.data = book['title']
            form.author.data = book['author']
            form.description.data = book['description']
            form.category.data = book['category_id']
            form.condition.data = book['condition']
            form.isbn.data = book['isbn'] if book['isbn'] else ''
            form.publisher.data = display_name  # Use display_name instead of username
            form.publication_year.data = book['publication_year'] if book['publication_year'] else ''
            # Remove the line that tries to set loan_duration data
        
        return render_template('edit_book.html', form=form, book=book)
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error in edit_book: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('my_books'))

@app.route('/delete_book/<int:book_id>', methods=['POST'])
def delete_book(book_id):
    if 'user_id' not in session:
        flash('Please sign in to delete books', 'error')
        return redirect(url_for('login'))
    
    try:
        # Check if book exists and belongs to user
        cursor.execute("""
            SELECT image_path FROM books 
            WHERE id = %s AND owner_id = %s
        """, (book_id, session['user_id']))
        book = cursor.fetchone()
        
        if not book:
            flash('Book not found or you do not have permission to delete it', 'error')
            return redirect(url_for('my_books'))
        
        # Delete associated image if it exists
        if book[0]:  # image_path
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], book[0].split('/')[-1])
            if os.path.exists(image_path):
                os.remove(image_path)
        
        # First delete related records from exchanges table
        cursor.execute("""
            DELETE FROM exchanges WHERE book_id = %s
        """, (book_id,))
        
        # Then delete related records from reviews table
        cursor.execute("""
            DELETE FROM reviews WHERE book_id = %s
        """, (book_id,))
        
        # Delete from favorites table
        cursor.execute("""
            DELETE FROM favorites WHERE book_id = %s
        """, (book_id,))
        
        # Delete from messages table
        cursor.execute("""
            DELETE FROM messages WHERE book_id = %s
        """, (book_id,))
        
        # Finally delete the book
        cursor.execute("""
            DELETE FROM books WHERE id = %s AND owner_id = %s
        """, (book_id, session['user_id']))
        
        conn.commit()
        flash('Book deleted successfully!', 'success')
        
    except Exception as e:
        conn.rollback()
        flash('An error occurred while deleting the book. Please try again.', 'error')
        app.logger.error(f"Error deleting book: {str(e)}")
    
    return redirect(url_for('my_books'))

@app.route('/favorites')
def favorites():
    if 'user_id' not in session:
        flash('Please sign in to view your favorites', 'error')
        return redirect(url_for('login'))
    
    # Get favorite books
    cursor.execute("""
        SELECT b.*, 
               u.username as owner_name,
               COALESCE(u.display_name, u.username) as owner_display_name,
               c.name as category_name,
               COALESCE(AVG(r.rating), 0) as avg_rating,
               COUNT(r.id) as review_count
        FROM favorites f
        JOIN books b ON f.book_id = b.id
        JOIN users u ON b.owner_id = u.id
        LEFT JOIN book_categories c ON b.category_id = c.id
        LEFT JOIN reviews r ON b.id = r.book_id
        WHERE f.user_id = %s
        GROUP BY b.id, u.username, u.display_name, c.name
        ORDER BY b.added_date DESC
    """, (session['user_id'],))
    
    books = cursor.fetchall()
    
    column_names = [desc[0] for desc in cursor.description]
    books_list = []
    for book in books:
        book_dict = {}
        for i, value in enumerate(book):
            book_dict[column_names[i]] = value
        books_list.append(book_dict)
    
    return render_template('favorites.html', books=books_list)

@app.route('/update_user_info', methods=['POST'])
def update_user_info():
    if 'user_id' not in session:
        flash('Please sign in to update your information', 'error')
        return redirect(url_for('login'))

    display_name = request.form.get('display_name')
    email = request.form.get('email')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    try:
        # If password change is requested
        if current_password and new_password and confirm_password:
            # Verify current password
            cursor.execute("SELECT password FROM users WHERE id = %s", (session['user_id'],))
            stored_password_hash = cursor.fetchone()[0]
            
            if not bcrypt.check_password_hash(stored_password_hash, current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('account'))
            
            # Validate new password
            if len(new_password) < 6:
                flash('New password must be at least 6 characters long', 'error')
                return redirect(url_for('account'))
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return redirect(url_for('account'))
            
            # Hash new password
            new_password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            
            # Update user info including password
            cursor.execute("""
                UPDATE users 
                SET display_name = %s, email = %s, password = %s
                WHERE id = %s
            """, (display_name, email, new_password_hash, session['user_id']))
            
            flash('Profile and password updated successfully!', 'success')
        else:
            # Update user info without password change
            cursor.execute("""
                UPDATE users 
                SET display_name = %s, email = %s
                WHERE id = %s
            """, (display_name, email, session['user_id']))
            
            flash('Profile updated successfully!', 'success')

        conn.commit()
        session['display_name'] = display_name
        
    except Exception as e:
        conn.rollback()
        flash(f'An error occurred: {str(e)}', 'error')

    return redirect(url_for('account'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        flash('Please sign in to delete your account', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    password = request.form.get('password')
    
    # Verify password
    cursor.execute("SELECT password FROM users WHERE id = %s", (user_id,))
    stored_password_hash = cursor.fetchone()[0]
    
    if not bcrypt.check_password_hash(stored_password_hash, password):
        flash('Password is incorrect. Account deletion canceled.', 'error')
        return redirect(url_for('account'))
    
    try:
        # Начинаем транзакцию для безопасного удаления всех данных пользователя
        # Удаляем избранное
        cursor.execute("DELETE FROM favorites WHERE user_id = %s", (user_id,))
        
        # Получаем ID книг пользователя
        cursor.execute("SELECT id FROM books WHERE owner_id = %s", (user_id,))
        book_ids = [row[0] for row in cursor.fetchall()]
        
        # Для каждой книги удаляем связанные записи
        for book_id in book_ids:
            # Удаляем отзывы к книгам пользователя
            cursor.execute("DELETE FROM reviews WHERE book_id = %s", (book_id,))
            
            # Удаляем сообщения, связанные с книгами пользователя
            cursor.execute("DELETE FROM messages WHERE book_id = %s", (book_id,))
            
            # Удаляем обмены книг
            cursor.execute("DELETE FROM exchanges WHERE book_id = %s", (book_id,))
        
        # Удаляем все отзывы, написанные пользователем
        cursor.execute("DELETE FROM reviews WHERE reviewer_id = %s", (user_id,))
        
        # Удаляем все сообщения пользователя
        cursor.execute("DELETE FROM messages WHERE sender_id = %s OR receiver_id = %s", (user_id, user_id))
        
        # Удаляем книги пользователя
        cursor.execute("DELETE FROM books WHERE owner_id = %s", (user_id,))
        
        # Удаляем скрытые чаты
        cursor.execute("DELETE FROM hidden_chats WHERE user_id = %s OR other_user_id = %s", (user_id, user_id))
        
        # Наконец, удаляем самого пользователя
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        
        conn.commit()
        
        # Очищаем сессию
        session.clear()
        
        flash('Your account has been deleted successfully.', 'info')
        return redirect(url_for('home'))
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error deleting account: {str(e)}")
        flash('An error occurred while deleting your account. Please try again.', 'error')
        return redirect(url_for('account'))

@app.route('/messages')
def messages():
    if 'user_id' not in session:
        flash('Please sign in to view messages', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Updating query to include last message content
    cursor.execute("""
        WITH latest_messages AS (
            SELECT DISTINCT ON (
                CASE 
                    WHEN sender_id = %s THEN receiver_id
                    ELSE sender_id
                END
            ) 
            id,
            CASE 
                WHEN sender_id = %s THEN receiver_id
                ELSE sender_id
            END as other_user_id,
            sender_id,
            book_id,
            content,
            created_at
            FROM messages
            WHERE sender_id = %s OR receiver_id = %s
            ORDER BY other_user_id, created_at DESC
        )
        SELECT 
            lm.other_user_id,
            u.username as other_username,
            COALESCE(u.display_name, u.username) as display_name,
            b.id as book_id,
            b.title as book_title,
            lm.created_at as last_message_time,
            lm.content as last_message,
            lm.sender_id = %s as is_from_me,
            (SELECT COUNT(*) FROM messages 
             WHERE receiver_id = %s AND sender_id = lm.other_user_id AND is_read = FALSE) as unread_count
        FROM latest_messages lm
        JOIN users u ON lm.other_user_id = u.id
        LEFT JOIN books b ON lm.book_id = b.id
        WHERE NOT EXISTS (
            SELECT 1 FROM hidden_chats 
            WHERE user_id = %s AND other_user_id = lm.other_user_id
        )
        ORDER BY lm.created_at DESC
    """, (user_id, user_id, user_id, user_id, user_id, user_id, user_id))
    
    chats = []
    for row in cursor.fetchall():
        chats.append({
            'user_id': row[0],
            'username': row[1],
            'display_name': row[2],
            'book_id': row[3],
            'book_title': row[4],
            'last_message_time': row[5],
            'last_message': row[6],
            'is_from_me': row[7],
            'unread_count': row[8]
        })
    
    return render_template('messages.html', chats=chats)

@app.route('/chat/<int:receiver_id>', methods=['GET', 'POST'])
def chat(receiver_id):
    if 'user_id' not in session:
        flash('Please sign in to chat', 'error')
        return redirect(url_for('login'))
    
    sender_id = session['user_id']
    
    # Проверяем, что получатель существует и получаем его display_name
    cursor.execute("SELECT username, display_name FROM users WHERE id = %s", (receiver_id,))
    user = cursor.fetchone()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('messages'))
    
    # Используем display_name, если он есть, иначе username
    display_name = user[1] if user[1] else user[0]
    
    # Remove book auto-fetching from the chat route
    
    if request.method == 'POST':
        content = request.form.get('message')
        if content:
            try:
                # We still handle book_id from the form, but removed the preloading
                book_id = request.form.get('book_id')
                if book_id:
                    # Verify book ownership before sending
                    cursor.execute("SELECT owner_id FROM books WHERE id = %s", (book_id,))
                    book_owner = cursor.fetchone()
                    if not book_owner or book_owner[0] != sender_id:
                        flash('You can only share books that you own', 'error')
                        book_id = None  # Reset book_id if verification fails
                
                # Отправляем сообщение
                cursor.execute("""
                    INSERT INTO messages (sender_id, receiver_id, book_id, content)
                    VALUES (%s, %s, %s, %s)
                """, (sender_id, receiver_id, book_id, content))
                conn.commit()
                
                # Если это AJAX запрос, возвращаем JSON
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': True, 'message': {'content': content, 'created_at': datetime.datetime.now().strftime('%H:%M')}})
                
                # Иначе перезагружаем страницу
                return redirect(url_for('chat', receiver_id=receiver_id))
            except Exception as e:
                conn.rollback()
                app.logger.error(f"Error sending message: {str(e)}")
                flash('Failed to send message. Please try again.', 'error')
    
    # Отмечаем сообщения как прочитанные
    cursor.execute("""
        UPDATE messages 
        SET is_read = TRUE 
        WHERE sender_id = %s AND receiver_id = %s
    """, (receiver_id, sender_id))
    conn.commit()
    
    # Получаем историю сообщений с display_name
    cursor.execute("""
        SELECT m.id, m.sender_id, m.receiver_id, 
               COALESCE(u_sender.display_name, u_sender.username) as sender_name,
               COALESCE(u_receiver.display_name, u_receiver.username) as receiver_name, 
               m.content, m.created_at, m.edited_at,
               m.book_id, b.title as book_title, b.author as book_author, b.image_path as book_image
        FROM messages m
        JOIN users u_sender ON m.sender_id = u_sender.id
        JOIN users u_receiver ON m.receiver_id = u_receiver.id
        LEFT JOIN books b ON m.book_id = b.id
        WHERE (m.sender_id = %s AND m.receiver_id = %s) 
           OR (m.sender_id = %s AND m.receiver_id = %s)
        ORDER BY m.created_at
    """, (sender_id, receiver_id, receiver_id, sender_id))
    
    messages = []
    for row in cursor.fetchall():
        messages.append({
            'id': row[0],
            'sender_id': row[1],
            'receiver_id': row[2],
            'sender_name': row[3],
            'receiver_name': row[4],
            'content': row[5],
            'created_at': row[6],
            'edited_at': row[7],
            'book_id': row[8],
            'book_title': row[9],
            'book_author': row[10],
            'book_image': row[11],
            'is_mine': row[1] == sender_id
        })
    
    return render_template('chat.html', messages=messages, receiver={
        'id': receiver_id,
        'username': user[0],
        'display_name': display_name
    })

@app.route('/start_chat/<int:receiver_id>')
def start_chat(receiver_id):
    if 'user_id' not in session:
        flash('Please sign in to start a chat', 'error')
        return redirect(url_for('login'))
    
    # Remove book_id parameter from redirecting to chat
    return redirect(url_for('chat', receiver_id=receiver_id))

@app.route('/send_book/<int:book_id>/<int:receiver_id>', methods=['POST'])
def send_book(book_id, receiver_id):
    if 'user_id' not in session:
        flash('Please sign in to transfer a book', 'error')
        return redirect(url_for('login'))
    
    sender_id = session['user_id']
    
    # Проверяем, что книга существует и принадлежит пользователю
    cursor.execute("""
        SELECT status, owner_id FROM books WHERE id = %s
    """, (book_id,))
    book = cursor.fetchone()
    
    if not book:
        flash('Book not found', 'error')
        return redirect(url_for('chat', receiver_id=receiver_id))
    
    # Дополнительная проверка на то, что текущий пользователь является владельцем книги
    if book[1] != sender_id:
        flash('You do not have permission to transfer this book', 'error')
        app.logger.warning(f"Attempted unauthorized book transfer: User {sender_id} tried to send book {book_id} owned by {book[1]}")
        return redirect(url_for('chat', receiver_id=receiver_id))
    
    if book[0] != 'available':
        flash('This book is not available for transfer', 'error')
        return redirect(url_for('chat', receiver_id=receiver_id))
    
    try:
        # Создаем запись об обмене
        cursor.execute("""
            INSERT INTO exchanges (book_id, lender_id, borrower_id, status)
            VALUES (%s, %s, %s, 'completed')
        """, (book_id, sender_id, receiver_id))
        
        # Обновляем статус книги
        cursor.execute("""
            UPDATE books SET status = 'borrowed', owner_id = %s WHERE id = %s
        """, (receiver_id, book_id))
        
        # Отправляем системное сообщение
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, book_id, content)
            VALUES (%s, %s, %s, %s)
        """, (sender_id, receiver_id, book_id, "I've transferred this book to you!"))
        
        conn.commit()
        flash('Book successfully transferred!', 'success')
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error transferring book: {str(e)}")
        flash('Failed to transfer book. Please try again.', 'error')
    
    return redirect(url_for('chat', receiver_id=receiver_id))

@app.route('/get_unread_count')
def get_unread_count():
    if 'user_id' not in session:
        return jsonify({'unread_count': 0})
    
    user_id = session['user_id']
    
    cursor.execute("""
        SELECT COUNT(*) FROM messages 
        WHERE receiver_id = %s AND is_read = FALSE
    """, (user_id,))
    
    result = cursor.fetchone()
    count = result[0] if result is not None else 0
    return jsonify({'unread_count': count})

@app.route('/edit_message/<int:message_id>', methods=['POST'])
def edit_message(message_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Please sign in to edit messages'}), 401
        flash('Please sign in to edit messages', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Проверяем, что сообщение существует и принадлежит пользователю
    cursor.execute("""
        SELECT sender_id, receiver_id, content 
        FROM messages 
        WHERE id = %s
    """, (message_id,))
    
    message = cursor.fetchone()
    if not message or message[0] != user_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Message not found or you do not have permission to edit it'}), 403
        flash('Message not found or you do not have permission to edit it', 'error')
        return redirect(url_for('messages'))
    
    content = request.form.get('content')
    if not content or content.strip() == '':
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Message content cannot be empty'}), 400
        flash('Message content cannot be empty', 'error')
        return redirect(url_for('chat', receiver_id=message[1]))
    
    try:
        # Обновляем содержимое сообщения и устанавливаем edited_at
        cursor.execute("""
            UPDATE messages 
            SET content = %s, edited_at = NOW() 
            WHERE id = %s
        """, (content, message_id))
        conn.commit()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True})
        
        flash('Message updated successfully', 'success')
        return redirect(url_for('chat', receiver_id=message[1]))
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error updating message: {str(e)}")
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Failed to update message'}), 500
        
        flash('Failed to update message. Please try again.', 'error')
        return redirect(url_for('chat', receiver_id=message[1]))

@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Please sign in to delete messages'}), 401
        flash('Please sign in to delete messages', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Проверяем, что сообщение существует и принадлежит пользователю
    cursor.execute("""
        SELECT sender_id, receiver_id 
        FROM messages 
        WHERE id = %s
    """, (message_id,))
    
    message = cursor.fetchone()
    if not message or message[0] != user_id:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Message not found or you do not have permission to delete it'}), 403
        flash('Message not found or you do not have permission to delete it', 'error')
        return redirect(url_for('messages'))
    
    try:
        # Удаляем сообщение
        cursor.execute("DELETE FROM messages WHERE id = %s", (message_id,))
        conn.commit()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True})
        
        flash('Message deleted successfully', 'success')
        return redirect(url_for('chat', receiver_id=message[1]))
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error deleting message: {str(e)}")
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Failed to delete message'}), 500
        
        flash('Failed to delete message. Please try again.', 'error')
        return redirect(url_for('chat', receiver_id=message[1]))

@app.route('/new_chat')
def new_chat():
    if 'user_id' not in session:
        flash('Please sign in to start a chat', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Получаем список всех пользователей, кроме текущего
    cursor.execute("""
        SELECT id, username, display_name, university 
        FROM users 
        WHERE id != %s
        ORDER BY username
    """, (user_id,))
    
    users = []
    for row in cursor.fetchall():
        # Если display_name не задано, используем username
        display_name = row[2] if row[2] else row[1]
        users.append({
            'id': row[0],
            'username': row[1],
            'display_name': display_name,
            'university': row[3]
        })
    
    return render_template('new_chat.html', users=users)

@app.route('/send_message/<int:chat_id>', methods=['POST'])
def send_message(chat_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Please sign in to send messages'})
        flash('Please sign in to send messages', 'error')
        return redirect(url_for('login'))
    
    sender_id = session['user_id']
    content = request.form.get('content', '').strip()
    book_id = request.form.get('book_id', '')
    
    if not content:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Message cannot be empty'})
        flash('Message cannot be empty', 'error')
        return redirect(url_for('chat', receiver_id=chat_id))
    
    # Check if book exists and belongs to the sender
    book = None
    if book_id:
        try:
            # Verify book ownership before sending
            cursor.execute("""
                SELECT id, title, author, image_path, owner_id 
                FROM books 
                WHERE id = %s
            """, (book_id,))
            book_data = cursor.fetchone()
            
            if not book_data:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': False, 'error': 'Book not found'})
                flash('Book not found', 'error')
                return redirect(url_for('chat', receiver_id=chat_id))
            
            if book_data[4] != sender_id:
                # Log unauthorized attempt
                app.logger.warning(f"User {sender_id} attempted to share book {book_id} owned by {book_data[4]}")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': False, 'error': 'You can only share books that you own'})
                flash('You can only share books that you own', 'error')
                return redirect(url_for('chat', receiver_id=chat_id))
            
            # Book exists and user owns it
            image_path = book_data[3]
            if image_path and not image_path.startswith(('http://', 'https://')):
                # Convert relative path to absolute URL
                image_path = url_for('static', filename=image_path, _external=True)
            
            book = {
                'id': book_data[0],
                'title': book_data[1],
                'author': book_data[2],
                'image_path': image_path
            }
        except Exception as e:
            app.logger.error(f"Error checking book ownership: {str(e)}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': 'Error processing book information'})
            flash('Error processing book information', 'error')
            return redirect(url_for('chat', receiver_id=chat_id))
    
    try:
        # Record the message in the database
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, content, book_id)
            VALUES (%s, %s, %s, %s) RETURNING id, created_at
        """, (sender_id, chat_id, content, book_id if book else None))
        
        message_data = cursor.fetchone()
        message_id = message_data[0]
        created_at = message_data[1]
        
        conn.commit()
        
        # If it's an AJAX request, return a JSON response
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            response_data = {
                'success': True,
                'message': {
                    'id': message_id,
                    'content': content,
                    'created_at': created_at.strftime('%H:%M'),
                    'book': book
                }
            }
            return jsonify(response_data)
        
        # Otherwise, redirect back to the chat page
        flash('Message sent successfully', 'success')
        return redirect(url_for('chat', receiver_id=chat_id))
    
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error sending message: {str(e)}")
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Error sending message'})
        
        flash('Error sending message', 'error')
        return redirect(url_for('chat', receiver_id=chat_id))

@app.route('/hide_chat/<int:other_user_id>', methods=['POST'])
def hide_chat(other_user_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Please sign in to hide chats'}), 401
        flash('Please sign in to hide chats', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']

    try:
        # Добавляем запись о скрытом чате
        cursor.execute("""
            INSERT INTO hidden_chats (user_id, other_user_id)
            VALUES (%s, %s)
            ON CONFLICT (user_id, other_user_id) DO NOTHING
        """, (user_id, other_user_id))

        conn.commit()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True})

        flash('Chat hidden successfully', 'success')
        return redirect(url_for('messages'))
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error hiding chat: {str(e)}")

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Failed to hide chat'}), 500

        flash('Failed to hide chat. Please try again.', 'error')
        return redirect(url_for('messages'))

@app.route('/show_hidden_chats', methods=['GET'])
def show_hidden_chats():
    if 'user_id' not in session:
        flash('Please sign in to view hidden chats', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Получаем список скрытых чатов, теперь с display_name
    cursor.execute("""
        SELECT 
            h.other_user_id,
            u.username,
            u.display_name,
            h.hidden_at
        FROM hidden_chats h
        JOIN users u ON h.other_user_id = u.id
        WHERE h.user_id = %s
        ORDER BY h.hidden_at DESC
    """, (user_id,))

    hidden_chats = []
    for row in cursor.fetchall():
        hidden_chats.append({
            'user_id': row[0],
            'username': row[1],
            'display_name': row[2],
            'hidden_at': row[3]
        })

    return render_template('hidden_chats.html', hidden_chats=hidden_chats)

@app.route('/unhide_chat/<int:other_user_id>', methods=['POST'])
def unhide_chat(other_user_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Please sign in to unhide chats'}), 401
        flash('Please sign in to unhide chats', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']

    try:
        cursor.execute("""
            DELETE FROM hidden_chats
            WHERE user_id = %s AND other_user_id = %s
        """, (user_id, other_user_id))

        conn.commit()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': 'Chat is now visible'})

        # fallback for non-AJAX
        flash('Chat is now visible', 'success')
        return redirect(url_for('messages'))
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error unhiding chat: {str(e)}")

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Failed to unhide chat'}), 500

        flash('Failed to unhide chat. Please try again.', 'error')
        return redirect(url_for('show_hidden_chats'))

@app.route('/get_user_books_json', methods=['GET'])
def get_user_books_json():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    try:
        cursor.execute("""
            SELECT id, title, author, image_path
            FROM books
            WHERE owner_id = %s AND status = 'available'
            ORDER BY title
        """, (user_id,))
        
        books = []
        for row in cursor.fetchall():
            image_path = row[3]
            # Make sure we return full URLs for images
            if image_path and not image_path.startswith(('http://', 'https://')):
                image_path = url_for('static', filename=image_path, _external=True)
            else:
                image_path = url_for('static', filename='images/default_book.png', _external=True)
                
            books.append({
                'id': row[0],
                'title': row[1],
                'author': row[2],
                'image_path': image_path
            })
        
        return jsonify({'books': books})
    except Exception as e:
        app.logger.error(f"Error fetching user books: {str(e)}")
        return jsonify({'error': 'Failed to load books'}), 500

@app.route('/debug_sharing')
def debug_sharing():
    if 'user_id' not in session:
        return "Unauthorized", 401
    
    sender_id = session['user_id']
    
    # Тестовые сообщения
    logs = []
    
    # Проверяем что происходит при отправке сообщения с книгой
    book_id = request.args.get('book_id')
    
    if book_id:
        try:
            # Проверяем существование книги
            cursor.execute("SELECT id, title, author, owner_id, image_path FROM books WHERE id = %s", (book_id,))
            book = cursor.fetchone()
            
            if not book:
                logs.append(f"Книга с ID {book_id} не найдена")
            else:
                logs.append(f"Книга найдена: ID={book[0]}, Title={book[1]}, Author={book[2]}, Owner={book[3]}")
                
                # Проверяем владельца книги
                if book[3] != sender_id:
                    logs.append(f"Эта книга не принадлежит текущему пользователю (owner_id={book[3]}, sender_id={sender_id})")
                else:
                    logs.append(f"Пользователь {sender_id} является владельцем книги")
                    
                # Проверяем данные изображения
                logs.append(f"Путь к изображению: {book[4]}")
                
                # Возвращаем результат в формате JSON для проверки
                book_info = {
                    'id': book[0],
                    'title': book[1],
                    'author': book[2],
                    'owner_id': book[3],
                    'image_path': book[4]
                }
                logs.append(f"JSON для книги: {book_info}")
        except Exception as e:
            logs.append(f"Ошибка при проверке книги: {str(e)}")
    
    return "<br>".join(logs)

@app.route('/download_pdf/<int:book_id>')
def download_pdf(book_id):
    app.logger.info(f"Download PDF request for book_id: {book_id}")
    
    if 'user_id' not in session:
        flash('Please sign in to download books', 'error')
        return redirect(url_for('login'))
    
    # Get book details including pdf_path
    cursor.execute("""
        SELECT b.pdf_path, b.title
        FROM books b
        WHERE b.id = %s
    """, (book_id,))
    
    book = cursor.fetchone()
    
    if not book or not book[0]:  # Check if book exists and has a PDF
        flash('PDF not available for this book', 'error')
        return redirect(url_for('book_detail', book_id=book_id))
    
    pdf_path = book[0]
    book_title = book[1]
    
    # Check if file exists on disk
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_path.split('/')[-1])
    if not os.path.exists(file_path):
        flash('PDF file not found', 'error')
        return redirect(url_for('book_detail', book_id=book_id))
    
    # Log access to the PDF
    app.logger.info(f"User {session['user_id']} accessing PDF for book {book_id}")
    
    # Sanitize the filename (remove special characters)
    safe_title = "".join([c for c in book_title if c.isalpha() or c.isdigit() or c==' ']).rstrip()
    download_name = f"{safe_title}.pdf"
    
    # Get the 'view' parameter - if it's set to 'inline', display the PDF in the browser
    view_mode = request.args.get('view', 'download')
    
    if view_mode == 'inline':
        return send_file(file_path, mimetype='application/pdf')
    else:
        return send_file(file_path, as_attachment=True, download_name=download_name)

@socketio.on('join')
def on_join(data):
    """User joins a chat room"""
    user_id = data.get('user_id')
    receiver_id = data.get('receiver_id')
    
    # Create a unique room name (combination of both user IDs, sorted and joined)
    users = sorted([user_id, receiver_id])
    room = f"chat_{users[0]}_{users[1]}"
    
    join_room(room)
    # Also join user's personal room for notifications
    join_room(f"user_{user_id}")

@socketio.on('send_message')
def send_message(data):
    """Handle sending a message"""
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    book = data.get('book')
    
    # Save message to database
    book_id = book.get('id') if book else None
    
    try:
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, content, book_id)
            VALUES (%s, %s, %s, %s) RETURNING id, created_at
        """, (sender_id, receiver_id, content, book_id))
        
        message_data = cursor.fetchone()
        message_id = message_data[0]
        created_at = message_data[1]
        conn.commit()
        
        # Create response data
        response = {
            'id': message_id,
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'content': content,
            'time': created_at.strftime('%H:%M'),
            'edited': False,
            'book': book
        }
        
        # Emit message to the chat room
        users = sorted([sender_id, receiver_id])
        room = f"chat_{users[0]}_{users[1]}"
        emit('new_message', response, room=room)
        
        # Also emit to receiver's personal room for notifications
        emit('new_message_notification', {
            'sender_id': sender_id,
            'count': 1
        }, room=f"user_{receiver_id}")
    
    except Exception as e:
        app.logger.error(f"Error sending message via socket: {str(e)}")
        conn.rollback()

@socketio.on('edit_message')
def edit_message(data):
    """Handle editing a message"""
    message_id = data.get('id')
    content = data.get('content')
    user_id = data.get('user_id')
    
    try:
        # Verify user owns the message
        cursor.execute("""
            SELECT sender_id, receiver_id FROM messages 
            WHERE id = %s
        """, (message_id,))
        
        message = cursor.fetchone()
        if not message or message[0] != user_id:
            # User doesn't own this message
            return
        
        # Update the message
        cursor.execute("""
            UPDATE messages
            SET content = %s, edited_at = NOW()
            WHERE id = %s AND sender_id = %s
            RETURNING receiver_id
        """, (content, message_id, user_id))
        
        if cursor.rowcount == 0:
            return  # No update happened
            
        receiver_id = cursor.fetchone()[0]
        conn.commit()
        
        # Emit message update event
        users = sorted([user_id, receiver_id])
        room = f"chat_{users[0]}_{users[1]}"
        
        emit('message_updated', {
            'id': message_id,
            'content': content,
            'edited': True,
            'sender_id': user_id  # Include sender_id in the response
        }, room=room)
        
    except Exception as e:
        app.logger.error(f"Error editing message via socket: {str(e)}")
        conn.rollback()

@socketio.on('delete_message')
def delete_message(data):
    """Handle deleting a message"""
    message_id = data.get('id')
    user_id = data.get('user_id')
    
    try:
        # Verify user owns the message
        cursor.execute("""
            SELECT sender_id, receiver_id FROM messages 
            WHERE id = %s
        """, (message_id,))
        
        message = cursor.fetchone()
        if not message or message[0] != user_id:
            # User doesn't own this message
            return
            
        receiver_id = message[1]
        
        # Delete the message
        cursor.execute("""
            DELETE FROM messages
            WHERE id = %s AND sender_id = %s
        """, (message_id, user_id))
        
        conn.commit()
        
        # Emit message delete event
        users = sorted([user_id, receiver_id])
        room = f"chat_{users[0]}_{users[1]}"
        
        emit('message_deleted', {
            'id': message_id
        }, room=room)
        
    except Exception as e:
        app.logger.error(f"Error deleting message via socket: {str(e)}")
        conn.rollback()

@socketio.on('mark_read')
def mark_message_read(data):
    """Mark messages as read"""
    user_id = data.get('user_id')
    message_id = data.get('message_id')
    
    try:
        # Get sender of the message
        cursor.execute("""
            SELECT sender_id FROM messages 
            WHERE id = %s AND receiver_id = %s
        """, (message_id, user_id))
        
        result = cursor.fetchone()
        if not result:
            return
            
        sender_id = result[0]
        
        # Mark this and all older unread messages from the same sender as read
        cursor.execute("""
            UPDATE messages 
            SET is_read = TRUE 
            WHERE sender_id = %s AND receiver_id = %s AND is_read = FALSE
        """, (sender_id, user_id))
        
        if cursor.rowcount > 0:
            conn.commit()
            
            # Emit read receipt event
            users = sorted([user_id, sender_id])
            room = f"chat_{users[0]}_{users[1]}"
            
            emit('message_read', {
                'reader_id': user_id,
                'sender_id': sender_id
            }, room=room)
            
    except Exception as e:
        app.logger.error(f"Error marking message as read: {str(e)}")
        conn.rollback()

@app.route('/api/books')
def api_books():
    sort_by = request.args.get('sort', 'recent')
    base_query = """
        SELECT b.*, u.username as owner_name, 
               COALESCE(u.display_name, u.username) as owner_display_name,
               c.name as category_name,
               COALESCE(AVG(r.rating), 0) as avg_rating, 
               COUNT(r.id) as review_count
        FROM books b
        JOIN users u ON b.owner_id = u.id
        LEFT JOIN book_categories c ON b.category_id = c.id
        LEFT JOIN reviews r ON b.id = r.book_id
        WHERE b.status = 'available'
        GROUP BY b.id, u.username, u.display_name, c.name
    """
    if sort_by == 'rating':
        order_clause = "ORDER BY avg_rating DESC, review_count DESC, b.added_date DESC"
    elif sort_by == 'popular':
        order_clause = "ORDER BY review_count DESC, b.added_date DESC"
    else:
        order_clause = "ORDER BY COALESCE(b.added_date, NOW()) DESC"
    full_query = f"{base_query} {order_clause}"
    cursor.execute(full_query)
    column_names = [desc[0] for desc in cursor.description]
    books = [dict(zip(column_names, row)) for row in cursor.fetchall()]
    return jsonify({'books': books})

# Modify the run line to use socketio
if __name__ == '__main__':
    socketio.run(app, debug=True)
