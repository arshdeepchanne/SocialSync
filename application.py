import os

import mysql.connector
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required


# Connect database
db = mysql.connector.connect(
  host="localhost",
  user="root",
  password="rootpassword",
  database="meetgreet"
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


@app.route("/")
@login_required
def index():
    # """Show portfolio of stocks"""

    # # Query the database for logged in user's stock holdings
    # portfolio = db.execute("SELECT symbol, total_shares FROM stocks WHERE user_id=?", session["user_id"])

    # # Query the database for logged in user's cash
    # cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])

    # cash_left = cash[0]["cash"]

    # # Look up the current price of each stock and calculate the total holdings of the user
    # total_holdings = 0
    # for stock in portfolio:
    #     quote = lookup(stock["symbol"])
    #     stock["name"] = quote["name"]
    #     stock["price"] = quote["price"]
    #     stock["total_hold"] = stock["price"] * stock["total_shares"]
    #     total_holdings += stock["total_hold"]

    # total_holdings += cash_left

    # return render_template("index.html", portfolio=portfolio, cash=cash_left, total=total_holdings)
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
@app.route("/login")
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
        cursor.execute("SELECT * FROM users")
        print("here", cursor.fetchall())
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
@app.route("/register")
def register():
    """Register user"""

    if request.method == "POST":

        # Get the username, password and confirmation password from the HTML form.
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
        cursor.execute("INSERT INTO users (uid, hash) VALUES(%s, %s)", (uid, generate_password_hash(password)))

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


# @app.route("/profile", methods=["GET", "POST"])
# @login_required
# def profile():
#     """SHOW USER PROFILE"""

#     if request.method == "POST":

#         old_pass = request.form.get("old_pass")
#         new_pass = request.form.get("new_pass")
#         confirm_pass = request.form.get("confirm_pass")

#         user = db.execute("SELECT username, hash FROM users WHERE id = ?", session["user_id"])

#         if not old_pass or old_pass == " ":
#             return apology("Old password field is blank.")

#         elif not check_password_hash(user[0]["hash"], old_pass):
#             return apology("Old password is wrong!")

#         elif not new_pass or not confirm_pass or new_pass == " " or confirm_pass == " ":
#             return apology("New password field is blank")

#         elif new_pass != confirm_pass:
#             return apology("Confirmation password does not match with new password.")

#         elif check_password_hash(user[0]["hash"], new_pass):
#             return apology("New password cannot be same as the old password.")

#         db.execute("UPDATE users SET hash=? WHERE id=?", generate_password_hash(new_pass), session["user_id"])

#         flash("Password Updated!")

#         return redirect("/")

#     else:
#         user = db.execute("SELECT username, hash FROM users WHERE id = ?", session["user_id"])
#         return render_template("profile.html", user=user[0]["username"])


# @app.route("/delete", methods=["POST"])
# @login_required
# def delete():
#     if request.method == "POST":

#         user = request.form.get("delete")

#         db.execute("DELETE FROM stocks WHERE user_id=?", session["user_id"])

#         db.execute("DELETE FROM transactions WHERE user_id=?", session["user_id"])

#         db.execute("DELETE FROM users WHERE id=?", session["user_id"])

#         flash("Account Deleted!")

#         return redirect("/login")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
