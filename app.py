from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mysqldb import MySQL
import MySQLdb.cursors
import MySQLdb
import re
from functools import wraps
from flask import jsonify
from flask import request

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Hondacrv@14'
app.config['MYSQL_DB'] = 'club_management'
app.config['SECRET_KEY'] = 'dev_secret_key'

mysql = MySQL(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'



class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

def log_action(user_id, action):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(
        "INSERT INTO audit_log (user_id, action) VALUES (%s, %s)",
        (user_id, action)
    )
    mysql.connection.commit()


@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
    account = cursor.fetchone()
    if account:
        return User(id=account['user_id'], username=account['username'], email=account['email'], role=account['role'])
    return None


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'club_admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function



@app.route('/')
def index():
    return render_template('index.html')


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM users WHERE username = %s AND password = %s',
            (username, password)
        )
        account = cursor.fetchone()

        if account:
            user = User(account['user_id'], account['username'], account['email'], account['role'])
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            msg = 'Incorrect username or password!'
    return render_template('login.html', msg=msg)



# register
@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ""
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only letters and numbers!'
        else:
            cursor.execute(
                "INSERT INTO users (username, password, email, role) VALUES (%s, %s, %s, 'student')",
                (username, password, email)
            )
            mysql.connection.commit()
            msg = 'Successfully registered!'
    return render_template('register.html', msg=msg)

# LOGOUT
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))



# DASHBOARD REDIRECT

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'club_admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('profile'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# LIST CLUBS (STUDENT)

@app.route('/clubs')
@login_required
def clubs():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("SELECT club_id, club_name, description FROM clubs ORDER BY club_name")
    clubs = cur.fetchall()

    cur.execute("""
        SELECT club_id, status
        FROM club_members
        WHERE user_id = %s
    """, (current_user.id,))
    memberships = {row['club_id']: row for row in cur.fetchall()}

    return render_template('clubs.html', clubs=clubs, memberships=memberships)


# STUDENT SEND JOIN REQUEST

@app.route('/clubs/<int:club_id>/join', methods=['POST'])
@login_required
def join_club(club_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Make sure the club exists
    cur.execute("SELECT club_id FROM clubs WHERE club_id = %s", (club_id,))
    club = cur.fetchone()
    if not club:
        flash("That club does not exist.", "error")
        return redirect(url_for('clubs'))

    # Check if user is already a member or has a pending request
    cur.execute("""
        SELECT * FROM club_members
        WHERE user_id = %s AND club_id = %s
    """, (current_user.id, club_id))
    membership = cur.fetchone()

    if membership:
        if membership['status'] == 'active':
            flash("You are already a member of this club.", "info")
        else:
            flash("You already have a pending request for this club.", "info")
    else:
        # Create a pending membership
        cur.execute("""
            INSERT INTO club_members (user_id, club_id, status)
            VALUES (%s, %s, 'pending')
        """, (current_user.id, club_id))
        mysql.connection.commit()

        # Get club name for logging
        cur.execute("SELECT club_name FROM clubs WHERE club_id = %s", (club_id,))
        club_row = cur.fetchone()
        club_name = club_row['club_name'] if club_row else f"Club ID {club_id}"

        # Log the action
        log_action(current_user.id, f"Requested to join club '{club_name}' ")

        flash("Request submitted.", "success")

    return redirect(url_for('clubs'))


# STUDENT ANNOUNCEMENTS

@app.route('/announcements')
@login_required
def announcements():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("""
        SELECT a.announcement_id, a.title, a.content, a.created_at, c.club_name
        FROM club_announcements a
        JOIN clubs c ON c.club_id = a.club_id
        WHERE a.club_id IN (
            SELECT club_id FROM club_members
            WHERE user_id=%s AND status='active'
        )
        ORDER BY a.created_at DESC
    """, (current_user.id,))
    ann = cur.fetchall()


    return render_template('announcements.html', announcements=ann)




# ADMIN DASHBOARD

@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("""
        SELECT club_id, club_name 
        FROM clubs 
        WHERE created_by = %s 
        ORDER BY club_name
    """, (current_user.id,))
    my_clubs = cur.fetchall()

    summary = []
    for club in my_clubs:
        cid = club['club_id']

        cur.execute("SELECT COUNT(*) AS cnt FROM club_members WHERE club_id=%s AND status='active'", (cid,))
        total_active = cur.fetchone()['cnt']

        cur.execute("SELECT COUNT(*) AS cnt FROM club_members WHERE club_id=%s AND status='pending'", (cid,))
        total_pending = cur.fetchone()['cnt']

        cur.execute("select count(*) as cnt from  club_announcements where club_id=%s", (cid,))
        announcements_count = cur.fetchone()['cnt']

        summary.append({
            'club_id': cid,
            'club_name': club['club_name'],
            'total_active': total_active,
            'total_pending': total_pending,
            'announcements_count': announcements_count
        })

    return render_template('admin_dashboard.html', summary=summary)

# Admin remove member

@app.route('/admin/members/<int:member_id>/remove', methods=['POST'])
@login_required
@admin_required
def admin_remove_member(member_id):
    club_id = request.form.get('club_id', type=int)

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # confirm this admin owns the club
    cur.execute(
        "SELECT club_id FROM clubs WHERE club_id=%s AND created_by=%s",
        (club_id, current_user.id)
    )
    if not cur.fetchone():
        abort(403)

    # Get username
    cur.execute("""
        SELECT u.username FROM club_members cm JOIN users u ON u.user_id = cm.user_id WHERE cm.member_id = %s AND cm.club_id = %s
    """, (member_id, club_id))
    member_row = cur.fetchone()
    member_username = member_row['username'] if member_row else "Unknown"

    # Get club name
    cur.execute("SELECT club_name FROM clubs WHERE club_id=%s", (club_id,))
    club_row = cur.fetchone()
    club_name = club_row['club_name'] if club_row else f"Club ID {club_id}"

    # remove member
    cur.execute("DELETE FROM club_members WHERE member_id=%s AND club_id=%s", (member_id, club_id))
    mysql.connection.commit()

    
    log_action(current_user.id, f"Removed user '{member_username}' from club '{club_name}'")

    flash("Member removed.", "warning")
    return redirect(url_for('admin_members', club_id=club_id))

# ADMIN: VIEW MEMBERS

@app.route('/admin/members')
@login_required
@admin_required
def admin_members():
    club_id = request.args.get('club_id', type=int)
    if not club_id:
        return redirect(url_for('admin_dashboard'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("SELECT club_id FROM clubs WHERE club_id=%s AND created_by=%s",
                (club_id, current_user.id))
    if not cur.fetchone():
        abort(403)

    cur.execute("""
        SELECT cm.member_id, u.user_id, u.username, u.email, cm.status, cm.joined_at
        FROM club_members cm
        JOIN users u ON u.user_id = cm.user_id
        WHERE cm.club_id = %s
        ORDER BY cm.status, u.username
    """, (club_id,))
    members = cur.fetchall()

    return render_template('admin_members.html', members=members, club_id=club_id)


# ADMIN: APPROVE JOIN REQUEST

@app.route('/admin/members/<int:req_id>/approve', methods=['POST'])
@login_required
@admin_required
def admin_approve_request(req_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    club_id = request.form.get('club_id', type=int)
    if not club_id:
        abort(400)

    cur.execute(
        "SELECT club_id FROM clubs WHERE club_id = %s AND created_by = %s",
        (club_id, current_user.id)
    )
    if not cur.fetchone():
        abort(403)

    # Approve the member
    cur.execute("""
        UPDATE club_members
        SET status = 'active'
        WHERE member_id = %s AND club_id = %s
    """, (req_id, club_id))
    mysql.connection.commit()

    cur.execute("select username from users where user_id = (select user_id from club_members where member_id=%s)", (req_id,))
    member_username = cur.fetchone()['username']

    cur.execute("select club_name from clubs where club_id=%s", (club_id,))
    club_name = cur.fetchone()['club_name']

    log_action(current_user.id, f"Approved member '{member_username}' for club '{club_name}' ")

    flash("Member approved.", "success")
    return redirect(url_for('admin_members', club_id=club_id))

# admin reject join request
@app.route('/admin/members/<int:member_id>/deny', methods=['POST'])
@login_required
@admin_required
def admin_deny_member(member_id):
    club_id = request.form.get('club_id', type=int)
    if not club_id:
        abort(400)

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT club_id FROM clubs WHERE club_id = %s AND created_by = %s", (club_id, current_user.id))
    if not cur.fetchone():
        abort(403)

    # Get user name
    cur.execute(""" select u.username from club_members cm join users u on u.user_id = cm.user_id where cm.member_id = %s and cm.club_id = %s and cm.status = 'pending'""", (member_id, club_id))
    member_row = cur.fetchone()
    member_username = member_row['username'] if member_row else "Unknown"

    # Get club name
    cur.execute("SELECT club_name FROM clubs WHERE club_id=%s", (club_id,))
    club_row = cur.fetchone()
    club_name = club_row['club_name'] if club_row else f"Club ID {club_id}"

    # Delete the pending request
    cur.execute("DELETE FROM club_members WHERE member_id = %s AND club_id = %s AND status = 'pending'", (member_id, club_id))
    mysql.connection.commit()

    log_action(current_user.id, f"Denied user '{member_username}' from joining club '{club_name}'")


    flash("Join request denied.", "warning")

    return redirect(url_for('admin_members', club_id=club_id))


# ADMIN: POST ANNOUNCEMENT

@app.route('/admin/announcements/new', methods=['GET','POST'])
@login_required
@admin_required
def admin_new_announcement():
    club_id = request.args.get('club_id', type=int) if request.method == 'GET' else request.form.get('club_id', type=int)

    if not club_id:
        flash("Pick a club.", "info")
        return redirect(url_for('admin_dashboard'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("SELECT club_id FROM clubs WHERE club_id=%s AND created_by=%s",
                (club_id, current_user.id))
    if not cur.fetchone():
        abort(403)

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        cur.execute("""
            INSERT INTO club_announcements (club_id, title, content, created_by)
            VALUES (%s, %s, %s, %s)
        """, (club_id, title, content, current_user.id))
        mysql.connection.commit()

        # Get club name for logs
        cur.execute("SELECT club_name FROM clubs WHERE club_id=%s", (club_id,))
        club_row = cur.fetchone()
        club_name = club_row['club_name'] if club_row else f"Club ID {club_id}"

        log_action(current_user.id, f"Posted announcement to {club_name}")

        flash("Announcement posted.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_announcement_new.html', club_id=club_id)




#Delete announcements by Admin
@app.route('/announcements/<int:announcement_id>/remove', methods=['POST'])
@login_required
@admin_required
def announcements_delete(announcement_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("""
        SELECT a.*, c.club_name, c.created_by 
        FROM club_announcements a
        JOIN clubs c ON a.club_id = c.club_id
        WHERE a.announcement_id = %s
    """, (announcement_id,))
    
    announcement = cur.fetchone()

    if not announcement:
        flash("Announcement not found.", "error")
        return redirect(url_for('admin_dashboard'))

    if announcement['created_by'] != current_user.id:
        abort(403)

    #Delete announcement
    cur.execute("DELETE FROM club_announcements WHERE announcement_id = %s", (announcement_id,))
    mysql.connection.commit()

    log_action(current_user.id, f"Deleted announcement '{announcement['title']}' from club '{announcement['club_name']}'")

    flash("Announcement removed successfully.", "success")
    return redirect(url_for('announcements'))






#admin create new club
@app.route('/admin/clubs/new', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_new_club():
    if request.method == 'POST':
        club_name = request.form.get('club_name', '').strip()
        description = request.form.get('description', '').strip()

        if not club_name:
            flash("Club name is required.", "error")
            return redirect(url_for('admin_new_club'))
        if len(club_name) > 100:
            flash("Club name must be 100 characters or less.", "error")
            return redirect(url_for('admin_new_club'))

        try:
            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cur.execute("""
                INSERT INTO clubs (club_name, description, created_by)
                VALUES (%s, %s, %s)
            """, (club_name, description, current_user.id))
            mysql.connection.commit()

            new_club_id = cur.lastrowid

            cur.execute("""
                INSERT INTO club_members (user_id, club_id, status)
                VALUES (%s, %s, 'active')
            """, (current_user.id, new_club_id))
            mysql.connection.commit()

            flash("Club created successfully!", "success")
            return redirect(url_for('admin_dashboard'))

        except MySQLdb.IntegrityError:
            mysql.connection.rollback()
            flash("A club with that name already exists. Please choose a different name.", "error")
            return redirect(url_for('admin_new_club'))

    return render_template('admin_club_new.html')




#Delete club by Admin
@app.route('/clubs/<int:club_id>/remove', methods=['POST'])
@login_required
@admin_required
def clubs_delete(club_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cur.execute("""SELECT club_id, club_name, created_by FROM clubs WHERE club_id = %s""", (club_id,))
    
    club = cur.fetchone()

    if not club:
        flash("Club not found.", "error")
        return redirect(url_for('admin_dashboard'))

    # confirm this admin owns the club
    if club['created_by'] != current_user.id:
        abort(403)

    #Delete club
    cur.execute("DELETE FROM clubs WHERE club_id = %s", (club_id,))
    mysql.connection.commit()

    log_action(current_user.id, f"Deleted Club '{club['club_name']}'")

    flash("Clubs removed successfully.", "success")
    return redirect(url_for('admin_dashboard'))




# ADMIN: VIEW AUDIT LOGS
@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Filters
    username = request.args.get('username', '').strip()
    action = request.args.get('action', '').strip()

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    # WHERE clause
    where_clauses = []
    params = []

    if username:
        where_clauses.append("u.username LIKE %s")
        params.append(f"%{username}%")

    if action:
        where_clauses.append("a.action LIKE %s")
        params.append(f"%{action}%")

    
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)
    else:
        where_sql = ""  

    # Count
    count_query = f"""
        SELECT COUNT(*) AS total
        FROM audit_log a
        LEFT JOIN users u ON a.user_id = u.user_id
        {where_sql}
    """
    cur.execute(count_query, params)
    total = cur.fetchone()['total']
    total_pages = (total + per_page - 1) // per_page

    # Data
    data_query = f"""
        SELECT a.action, a.timestamp, u.username
        FROM audit_log a
        LEFT JOIN users u ON a.user_id = u.user_id
        {where_sql}
        ORDER BY a.timestamp DESC
        LIMIT %s, %s
    """

    cur.execute(data_query, params + [offset, per_page])
    logs = cur.fetchall()

    return render_template(
        'admin_logs.html',
        logs=logs,
        username=username,
        action=action,
        page=page,
        total_pages=total_pages,
        total=total
    )


if __name__ == '__main__':
    app.run(debug=True)
