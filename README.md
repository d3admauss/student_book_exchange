[English](README.md) | [Русский](README.ru.md)
# Student Book Exchange

## Overview 
Student Book Exchange is a Flask and Python based web application designed to facilitate book sharing and exchanges among students. It provides a electronic library platform where students can list their books, search for books they need, review books, and directly communicate with other users to exchange books.

## Features

### User Management
- Registration and authentication
- Profile customization
- University affiliation

### Book Management
- Add, edit, and remove books
- Upload book covers and PDF files
- Categorize books by subject

### Social Features
- Real-time messaging between users
- Book reviews and ratings
- Favorite books collection
- Book transfer between users

### Search and Discovery
- Advanced search with multiple filters
- Browse by categories
- Sort by title, author, rating, or recency

## Technology Stack
- **Backend**: Flask (Python)
- **Database**: PostgreSQL
- **Frontend**: HTML, CSS, JavaScript
- **Authentication**: Flask-Bcrypt
- **Form Handling**: Flask-WTF
- **File Uploads**: Werkzeug
- **Real-Time Chat**: flask-socketio

## Installation and Setup

### Prerequisites
- Python 3.7+
- PostgreSQL
- pip (Python package manager)

### Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/Sxlken/student_book_exchange.git
   ```
   
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   
3. Configure PostgreSQL:
   - Create a database named `student_library`
   - Update database connection details in `site/app.py`:
     ```python
     conn = psycopg2.connect(
         host="localhost",
         database="student_library",
         user="your_username",
         password="your_password"
     )
     ```

4. Create necessary directories:
   ```bash
   mkdir -p site/static/uploads
   ```

5. Run the application:
   ```bash
   cd site
   flask run
   ```

6. Open http://localhost:5000 in your browser.
  
```bash
Light Mode:
```
![image](https://github.com/user-attachments/assets/2f62bbe5-460c-4f3a-a3d9-f5d74ba320ad)

```bash
Dark Mode:
```
![image](https://github.com/user-attachments/assets/a0e5de92-b29a-4bc4-9c47-aeef9205ed37)

