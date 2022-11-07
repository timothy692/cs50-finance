import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import re

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

uri = os.getenv("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://")
db = SQL(uri)

db.execute("""CREATE TABLE IF NOT EXISTS history (
                user_id INTEGER NOT NULL,
                symbol TINYTEXT NOT NULL,
                total NUMERIC NOT NULL,
                shares NUMERIC NOT NULL,
                time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );""")

db.execute("""CREATE TABLE IF NOT EXISTS shares (
                user_id INTEGER NOT NULL,
                symbol TINYTEXT NOT NULL,
                shares NUMERIC NOT NULL
                );""")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    rows = db.execute("SELECT * FROM shares WHERE user_id = ?", session["user_id"])
    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]

    cash = float(user["cash"])
    stocks = 0

    for row in rows:
        req = lookup(row["symbol"])
        row["name"] = req["name"]
        row["price"] = req["price"]
        row["total"] = float(row["shares"]) * float(row["price"])
        stocks += row["total"]

    return render_template("index.html", stocks=rows, cash=cash, grandtotal=cash + stocks)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("symbol cannot be blank")
        elif not request.form.get("shares"):
            return apology("shares cannot be blank")

        req = lookup(request.form.get("symbol"))
        if req is None:
            return apology("invalid symbol")

        shares = request.form.get("shares")

        # check if int
        if not shares.isnumeric():
            return apology("shares has to be a number")

        if int(shares) < 1:
            return apology("minimum shares to buy is 1")

        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]
        price = float(req["price"])
        total = price * int(shares)

        if user["cash"] < total:
            return apology("not enough money")

        # Update user's cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", float(user["cash"] - total), session["user_id"])

        # Update user's shares
        owned = db.execute("SELECT * FROM shares WHERE user_id = ? AND symbol = ?", session["user_id"], req["symbol"])

        # User does not own any shares of this company
        if len(owned) == 0:
            db.execute("INSERT INTO shares (user_id, symbol, shares) VALUES (?, ?, ?)", session["user_id"], req["symbol"], shares)
        # User owns shars, update it
        else:
            db.execute("UPDATE shares SET shares = ? WHERE user_id = ? AND symbol = ?",
                       owned[0]["shares"] + shares, session["user_id"], req["symbol"])

        # Add payment to history
        db.execute("INSERT INTO history (user_id, symbol, total, shares) VALUES (?, ?, ?, ?)",
                   session["user_id"], req["symbol"], total, shares)

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    data = db.execute("SELECT * FROM history WHERE user_id = ? ORDER BY time DESC", session["user_id"])

    for row in data:
        row["action"] = ({True: "SELL", False: "BUY"})[row["shares"] < 0]

    return render_template("history.html", history=data)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        req = lookup(request.form.get("symbol"))
        if not req:
            return apology("invalid symbol")

        return render_template("quoted.html", company=req["name"], symbol=req["symbol"], price=req["price"])
    else:
        return render_template("quote.html")


def ensure_requirements(passw):
    """ Ensure a password meets requirements """
    if len(passw) < 6:
        return False

    if re.search(r'^(?=[^A-Z]*[A-Z])(?=[^0-9]*[0-9])', passw):
        return True
    else:
        return False


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        if not username:
            return apology("username cannot be blank")

        row = db.execute("SELECT * from users WHERE username = ?", username)
        if len(row) != 0:
            return apology("username already exists")

        password = request.form.get("password")
        if not password or not request.form.get("confirmation"):
            return apology("password cannot be blank")

        if password != request.form.get("confirmation"):
            return apology("passwords must match")

        if not ensure_requirements(password):
            return apology("password does not meet requirements")

        phash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, phash)

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user = db.execute("SELECT * FROM shares WHERE user_id = ? ORDER BY symbol", session["user_id"])

    if request.method == "POST":
        shares = request.form.get("shares")
        symbol = request.form.get("symbol")

        if not any(d["symbol"] == symbol for d in user):
            return apology("no symbol selected")

        if shares is None:
            return apology("no shares selected")

        if not shares.isnumeric():
            return apology("shares has to be a number")

        if int(shares) < 1:
            return apology("minimum shares to buy is 1")

        user_shares = db.execute("SELECT shares FROM shares WHERE user_id = ? AND symbol = ?",
                                 session["user_id"], symbol)[0]["shares"]

        if int(user_shares) < int(shares):
            return apology("you don't own that many shares")

        price = lookup(symbol)["price"]
        # update cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", float(cash["cash"]) + (price * int(shares)), session["user_id"])

        # update shares
        new_shares = int(user_shares) - int(shares)
        if new_shares < 1:
            db.execute("DELETE FROM shares WHERE symbol = ? AND user_id = ?", symbol, session["user_id"])
        else:
            db.execute("UPDATE shares SET shares = ? WHERE user_id = ? AND symbol = ?", new_shares, session["user_id"], symbol)

        # add to history
        db.execute("INSERT INTO history (user_id, symbol, total, shares) VALUES (?, ?, ?, ?)",
                   session["user_id"], symbol, (price * int(shares)), -abs(int(shares)))

        return redirect("/")
    else:

        return render_template("sell.html", symbols=user)
