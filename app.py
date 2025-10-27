from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
from functools import wraps
from flask import abort



app = Flask(__name__)


login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.secret_key = 'TP'



class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE id = %s', (user_id,))
    account = cursor.fetchone()
    if account:
        return User(id=account['id'], username=account['username'], role=account['role'])
    return None



#Admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function



@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')




#Regular User
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,)
        )
        account = cursor.fetchone()

        if account:
            user = User(account['id'], account['username'], account['role'])
            login_user(user)
            msg = 'Logged in successfully!'
            return redirect(url_for('dashboard'))
        else:
            msg = 'Incorrect username / password !'
    return render_template('login.html', msg=msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
	msg = ""
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email':
		username = request.form['username']
		password = request.form['password']
		email = request.form['email']

		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
		account = cursor.fetchone()
		
		if account:
			msg = 'Account already exists !'
		elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
			msg = 'Invalid email address !'
		elif not re.match(r'[A-Za-z0-9]+', username):
			msg = 'name must contain only characters and numbers !'
		else:
			cursor.execute('INSERT INTO accounts VALUES \ (NULL, % s, % s, % s)', (username, password, email))
			
			mysql.connection.commit()
			msg = 'You have successfully registered !'
			
	elif request.method == 'POST':
		msg = 'Please fill out the form !'
		
	return render_template('register.html', msg=msg)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'sucess_logout')
    return redirect(url_for('index'))



@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')



@app.route('/profile')
@login_required
def profile():
     return render_template('profile.html')



'''@app.route('/update_profile', methods=['GET', 'POST'])
@login_required'''



if __name__ == '__main__':
    app.run(debug=True)