from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'secret_key'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Flask-Bcrypt
bcrypt = Bcrypt(app)

# Define a User class
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# Define an Admin class
class Admin(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# User loader function
@login_manager.user_loader
def load_user(user_id):
    db_path = os.path.join('D:\\', 'pygame', 'code', 'user_data.db')
    print(f"Database path: {db_path}")  # Debugging line to print the database path
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if user is an admin
    cursor.execute("SELECT id, username FROM admins WHERE id = ?", (user_id,))
    admin_data = cursor.fetchone()
    if admin_data:
        conn.close()
        return Admin(id=admin_data[0], username=admin_data[1])

    # If not an admin, check regular users
    cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data:
        return User(id=user_data[0], username=user_data[1])
    return None

# Function to fetch user data from the database
def get_users():
    db_path = os.path.join('D:\\', 'pygame', 'code', 'user_data.db')
    print(f"Database path: {db_path}")  # Debugging line to print the database path
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, current_level FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

@app.route('/')
@login_required
def dashboard():
    users = get_users()
    return render_template('users.html', users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db_path = os.path.join('D:\\', 'pygame', 'code', 'user_data.db')
        print(f"Database path: {db_path}")  # Debugging line to print the database path
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if the user is an admin
        cursor.execute("SELECT id, username, password FROM admins WHERE username = ?", (username,))
        admin_data = cursor.fetchone()

        if admin_data and bcrypt.check_password_hash(admin_data[2], password):
            admin = Admin(id=admin_data[0], username=admin_data[1])
            login_user(admin)
            conn.close()
            return redirect(url_for('dashboard'))

        # If not an admin, check regular users
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data and bcrypt.check_password_hash(user_data[2], password):
            user = User(id=user_data[0], username=user_data[1])
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
