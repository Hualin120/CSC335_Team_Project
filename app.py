from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
from functools import wraps
from flask import abort
from flask import jsonify


app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'club_management'
app.config['SECRET_KEY'] = 'dev_secret_key'
mysql = MySQL(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM user WHERE user_id = %s', (user_id,))
    account = cursor.fetchone()
    if account:
        return User(id=account['user_id'], username=account['username'], role=account['role'])
    return None



#Admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'club_admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function



@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(""" SELECT club_id, club_name FROM clubs WHERE created_by = %s ORDER BY club_name""", (current_user.id,))
    my_clubs = cur.fetchall()

    summary = []
    for club in my_clubs:
        cid = club['club_id']
        cur.execute( "SELECT COUNT(*) AS cnt FROM club_members WHERE club_id = %s AND status='active' ", (cid,))
        total_active = cur.fetchone()['cnt']

        cur.execute("SELECT COUNT(*) AS cnt FROM club_members WHERE club_id=%s AND status='pending'", (cid,))
        total_pending = cur.fetchone()['cnt']

        cur.execute("SELECT COUNT(*) AS cnt FROM club_members WHERE club_id=%s AND status='active' AND dues_paid=1", (cid,))
        dues_paid = cur.fetchone()['cnt']

        cur.execute("SELECT COUNT(*) AS cnt FROM club_members WHERE club_id=%s AND status='active' AND dues_paid=0", (cid,))
        dues_unpaid = cur.fetchone()['cnt']

        cur.execute("SELECT COUNT(*) AS cnt FROM events WHERE club_id=%s", (cid,))
        events_count = cur.fetchone()['cnt']

        # total RSVP “yes” across events (requires view v_event_yes_rsvps)
        cur.execute("""
            SELECT COALESCE(SUM(v.yes_count),0) AS yes_total
            FROM v_event_yes_rsvps v
            WHERE v.club_id = %s
        """, (cid,))
        total_yes = cur.fetchone()['yes_total']

        summary.append({
            'club_id': cid,
            'club_name': club['club_name'],
            'total_active': total_active,
            'total_pending': total_pending,
            'dues_paid': dues_paid,
            'dues_unpaid': dues_unpaid,
            'events_count': events_count,
            'total_yes_rsvp': total_yes
        })
    return render_template('admin_dashboard.html', summary=summary)




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
            'SELECT * FROM user WHERE username = %s AND password = %s', (username, password,)
        )
        account = cursor.fetchone()

        if account:
            user = User(account['user_id'], account['username'], account['role'])
            login_user(user)
            msg = 'Logged in successfully!'
            return redirect(url_for('dashboard'))
        else:
            msg = 'Incorrect username / password !'
    return render_template('login.html', msg=msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ""
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE username = %s', (username, ))
        account = cursor.fetchone()
        
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'name must contain only characters and numbers !'
        else:
            cursor.execute("INSERT INTO user (username, password, email, role) VALUES (%s, %s, %s, 'student')", (username, password, email))
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
    if current_user.role == 'club_admin':
        return redirect(url_for('admin_dashboard')) 
    return redirect (url_for('profile'))



@app.route('/profile')
@login_required
def profile():
     return render_template('profile.html')


# ---------- STUDENT: list all clubs (visible after login) ----------
@app.route('/clubs')
@login_required
def clubs():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT club_id, club_name, description FROM clubs ORDER BY club_name")
    clubs = cur.fetchall()

    # user’s current memberships so we can show status/dues beside each club
    cur.execute("""
        SELECT cm.club_id, cm.status, cm.dues_paid
        FROM club_members cm
        WHERE cm.user_id = %s
    """, (current_user.id,))
    memberships = {row['club_id']: row for row in cur.fetchall()}

    return render_template('clubs.html', clubs=clubs, memberships=memberships)



# ---------- STUDENT: request to join a club (status -> pending) ----------
@app.route('/clubs/<int:club_id>/join', methods=['POST'])
@login_required
def join_club(club_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # prevent duplicates
    cur.execute("SELECT member_id, status FROM club_members WHERE user_id=%s AND club_id=%s",
                (current_user.id, club_id))
    row = cur.fetchone()
    if row:
        flash(f"Already {row['status']} for this club.", "info")
    else:
        cur.execute("""
            INSERT INTO club_members (user_id, club_id, status, dues_paid)
            VALUES (%s, %s, 'pending', 0)
        """, (current_user.id, club_id))
        mysql.connection.commit()
        flash("Join request sent. An admin will review it.", "success")
    return redirect(url_for('clubs'))


# ---------- STUDENT: list events (visible to any logged-in user) ----------
@app.route('/events')
@login_required
def events():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT e.event_id, e.event_name, e.description, e.event_date, c.club_name,
               COALESCE(v.yes_count,0) AS yes_count
        FROM events e
        JOIN clubs c ON c.club_id = e.club_id
        LEFT JOIN v_event_yes_rsvps v ON v.event_id = e.event_id
        ORDER BY e.event_date DESC
    """)
    events = cur.fetchall()

    # fetch this user’s RSVPs so UI can show selected option
    cur.execute("SELECT event_id, rsvp FROM event_rsvps WHERE user_id=%s", (current_user.id,))
    my_rsvp = {r['event_id']: r['rsvp'] for r in cur.fetchall()}

    return render_template('events.html', events=events, my_rsvp=my_rsvp)


# ---------- STUDENT: RSVP yes/no/maybe ----------
@app.route('/events/<int:event_id>/rsvp', methods=['POST'])
@login_required
def rsvp_event(event_id):
    rsvp_val = request.form.get('rsvp', 'yes')
    if rsvp_val not in ('yes', 'no', 'maybe'):
        rsvp_val = 'yes'
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # upsert
    cur.execute("""
        INSERT INTO event_rsvps (event_id, user_id, rsvp)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE rsvp=VALUES(rsvp)
    """, (event_id, current_user.id, rsvp_val))
    mysql.connection.commit()
    flash("RSVP updated.", "success")
    return redirect(url_for('events'))


# ---------- STUDENT: announcements from clubs you belong to (active) ----------
@app.route('/announcements')
@login_required
def announcements():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT a.announcement_id, a.title, a.body, a.created_at, c.club_name
        FROM announcements a
        JOIN clubs c ON c.club_id = a.club_id
        WHERE a.club_id IN (
            SELECT club_id FROM club_members
            WHERE user_id=%s AND status='active'
        )
        ORDER BY a.created_at DESC
    """, (current_user.id,))
    ann = cur.fetchall()
    return render_template('announcements.html', announcements=ann)


# ---------- ADMIN: members list for a club ----------
@app.route('/admin/members')
@login_required
@admin_required
def admin_members():
    club_id = request.args.get('club_id', type=int)
    if not club_id:
        flash("Pick a club from your dashboard.", "info")
        return redirect(url_for('admin_dashboard'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # ownership check
    cur.execute("SELECT club_id FROM clubs WHERE club_id=%s AND created_by=%s", (club_id, current_user.id))
    if not cur.fetchone():
        abort(403)

    cur.execute("""
        SELECT cm.member_id, u.user_id, u.username, u.email, cm.status, cm.dues_paid, cm.joined_at
        FROM club_members cm
        JOIN user u ON u.user_id = cm.user_id
        WHERE cm.club_id = %s
        ORDER BY cm.status, u.username
    """, (club_id,))
    members = cur.fetchall()
    return render_template('admin_members.html', members=members, club_id=club_id)


@app.route('/admin/members/<int:member_id>/approve', methods=['POST'])
@login_required
@admin_required
def admin_approve_member(member_id):
    club_id = request.form.get('club_id', type=int)
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT club_id FROM clubs WHERE club_id=%s AND created_by=%s", (club_id, current_user.id))
    if not cur.fetchone(): abort(403)

    cur.execute("UPDATE club_members SET status='active' WHERE member_id=%s", (member_id,))
    mysql.connection.commit()
    flash("Member approved.", "success")
    return redirect(url_for('admin_members', club_id=club_id))

@app.route('/admin/members/<int:member_id>/deny', methods=['POST'])
@login_required
@admin_required
def admin_deny_member(member_id):
    club_id = request.form.get('club_id', type=int)
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT club_id FROM clubs WHERE club_id=%s AND created_by=%s", (club_id, current_user.id))
    if not cur.fetchone(): abort(403)

    cur.execute("DELETE FROM club_members WHERE member_id=%s", (member_id,))
    mysql.connection.commit()
    flash("Request denied.", "info")
    return redirect(url_for('admin_members', club_id=club_id))

@app.route('/admin/members/<int:member_id>/remove', methods=['POST'])
@login_required
@admin_required
def admin_remove_member(member_id):
    club_id = request.form.get('club_id', type=int)
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT club_id FROM clubs WHERE club_id=%s AND created_by=%s", (club_id, current_user.id))
    if not cur.fetchone(): abort(403)

    cur.execute("DELETE FROM club_members WHERE member_id=%s", (member_id,))
    mysql.connection.commit()
    flash("Member removed.", "warning")
    return redirect(url_for('admin_members', club_id=club_id))

@app.route('/admin/members/<int:member_id>/toggle_dues', methods=['POST'])
@login_required
@admin_required
def admin_toggle_dues(member_id):
    club_id = request.form.get('club_id', type=int)
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT club_id FROM clubs WHERE club_id=%s AND created_by=%s", (club_id, current_user.id))
    if not cur.fetchone(): abort(403)

    cur.execute("""
        UPDATE club_members
        SET dues_paid = CASE WHEN dues_paid=1 THEN 0 ELSE 1 END
        WHERE member_id=%s
    """, (member_id,))
    mysql.connection.commit()
    flash("Dues toggled.", "success")
    return redirect(url_for('admin_members', club_id=club_id))


# ---------- ADMIN: create event ----------
@app.route('/admin/events/new', methods=['GET','POST'])
@login_required
@admin_required
def admin_new_event():
    club_id = request.args.get('club_id', type=int) if request.method=='GET' else request.form.get('club_id', type=int)
    if not club_id:
        flash("Pick a club from your dashboard.", "info")
        return redirect(url_for('admin_dashboard'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT club_id FROM clubs WHERE club_id=%s AND created_by=%s", (club_id, current_user.id))
    if not cur.fetchone(): abort(403)

    if request.method == 'POST':
        event_name = request.form.get('event_name')
        description = request.form.get('description')
        event_date = request.form.get('event_date')  # YYYY-MM-DD
        cur.execute("""
            INSERT INTO events (club_id, event_name, description, event_date)
            VALUES (%s, %s, %s, %s)
        """, (club_id, event_name, description, event_date))
        mysql.connection.commit()
        flash("Event created.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_event_new.html', club_id=club_id)

# ---------- ADMIN: post announcement ----------
@app.route('/admin/announcements/new', methods=['GET','POST'])
@login_required
@admin_required
def admin_new_announcement():
    club_id = request.args.get('club_id', type=int) if request.method=='GET' else request.form.get('club_id', type=int)
    if not club_id:
        flash("Pick a club.", "info")
        return redirect(url_for('admin_dashboard'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT club_id FROM clubs WHERE club_id=%s AND created_by=%s", (club_id, current_user.id))
    if not cur.fetchone(): abort(403)

    if request.method == 'POST':
        title = request.form.get('title')
        body  = request.form.get('body')
        cur.execute("""
            INSERT INTO announcements (club_id, title, body, created_by)
            VALUES (%s, %s, %s, %s)
        """, (club_id, title, body, current_user.id))
        mysql.connection.commit()
        flash("Announcement posted.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_announcement_new.html', club_id=club_id)


'''@app.route('/update_profile', methods=['GET', 'POST'])
@login_required'''



if __name__ == '__main__':
    app.run(debug=True)