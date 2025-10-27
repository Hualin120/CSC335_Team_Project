from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL



app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])


@app.route('/logout')


@app.route('/dashboard')
@login_required
def


@app.route('/profile')
@login_required


@app.route('/update_profile', methods=['GET', 'POST'])
@login_required


@app.route('/logout ')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'sucess_logout')
    return redirect(url_for('index'))
