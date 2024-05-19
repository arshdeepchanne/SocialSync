import os

import mysql.connector
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required


# Connect database
db = mysql.connector.connect(
  host="localhost",
  user="root",
  password="rootpassword",
  database="socialsync"
)

# Create cursor
cursor = db.cursor(dictionary=True)
db.commit()

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.route("/", methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        ...

    else:
        cursor.execute("SELECT uid, name from users where id=(%s)", (session["user_id"],))
        user = cursor.fetchone()
        print(user)
        cursor.execute(
            """select users.name as uname, 
                    users.uid, users.name as uname, event_id, events.name as ename, 
                        events.description, events.event_time, events.creation_time,
                       events.venue from users, events where users.id = events.organiser_id"""
        )
        events = cursor.fetchall()
        
        cursor.execute(
            """select name, event_time, venue from events 
                where event_id in (
                    select event_id from joinees where user_id=(%s))""", (session["user_id"],)
            )
        joined_events = cursor.fetchall()
        print(joined_events)
        
        return render_template("index.html", events=events, user=user, joined_events=joined_events)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("uid"):
            return apology("must provide uid", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        cursor.execute("SELECT * FROM users WHERE uid = (%s)", (request.form.get("uid"), ))
        rows = cursor.fetchall()
        print(rows)
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Register if you haven't already!", category="error")
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        db.commit()

        flash("Login Successful!")
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # Get the username, password and confirmation password from the HTML form.
        name = request.form.get("username")
        uid = request.form.get("uid")
        password = request.form.get("password")
        confirm_pass = request.form.get("confirm_password")

        # Query the database to get the list of all users.
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        print("Users:", users)

        # Check if the username was submitted.
        if not uid or uid == ' ':
            return apology("Username cannot be blank")

        # Check if the username already exists.
        for user in users:
            if uid == user["uid"]:
                return apology("User already exists")

        # Ensure that passwords were submitted.
        if not password or not confirm_pass:
            return apology("Password cannot be blank")

        # Ensure that the password and confirmation password match.
        elif password != confirm_pass:
            return apology("Passwords do not match")

        # Register the user.
        cursor.execute("INSERT INTO users (uid, name, hash) VALUES(%s, %s, %s)", (uid, name, generate_password_hash(password)))

        # Query the database to get the id of the user.
        cursor.execute("SELECT id FROM users WHERE uid=(%s)", (uid, ))
        user = cursor.fetchall()
        print(user)
        # Remember the id of the logged in user.
        session["user_id"] = user[0]["id"]

        db.commit()
        
        flash("Registration Successful!")
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/create_event", methods=["GET", "POST"])
@login_required
def create_event():
    if request.method == "POST":
        ename = request.form.get("ename")
        desc = request.form.get("description")
        category = request.form.get("category")
        event_time = request.form.get("time")
        creation_time = datetime.now()
        venue = request.form.get("venue")
        
        print("Time:",event_time, type(event_time))
        # print(ename, desc, venue, category, event_time, creation_time, venue, sep="\n")

        cursor.execute(
            """INSERT INTO events (
                name, description, category, event_time, creation_time, organiser_id, venue
                ) VALUES(%s, %s, %s, %s, %s, %s, %s)""", 
                (ename, desc, category, event_time, creation_time, session["user_id"], venue)
        )
        db.commit()
        return redirect("/")
    
    else:
        return render_template("create_event.html")


@app.route("/join_event", methods=["GET", "POST"])
@login_required
def join_event():
    if request.method == "POST":
        event_id = request.form.get("form_id")

        print("here")
        cursor.execute("INSERT INTO joinees VALUES (%s, %s)", (session["user_id"], event_id))
        db.commit()

        print(f"{session["user_id"]} joined {event_id}")

        return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
