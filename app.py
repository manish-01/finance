import os
from tempfile import mkdtemp

from cs50 import SQL
from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   session)
from flask_session import Session
from werkzeug.exceptions import (HTTPException, InternalServerError,
                                 default_exceptions)
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    rows = db.execute("SELECT * FROM portfolio WHERE id = :id", id=session["user_id"])
    users = db.execute("SELECT * FROM users WHERE id = :id", id=session["user_id"])
    cash = users[0]["cash"]
    total = 0

    for row in rows:
        symbol = row["symbol"]
        shares = row["shares"]
        stock = lookup(symbol)
        price_t = float(stock["price"]) * shares
        db.execute("UPDATE portfolio SET price=:price WHERE id=:id AND symbol=:symbol",
                   price=float(stock["price"]), id=session["user_id"], symbol=row["symbol"])
        total += price_t

    TOTAL = total + cash
    return render_template("index.html", rows=rows, cash=usd(cash), TOTAL=usd(TOTAL))


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow user to change her password"""

    if request.method == "POST":

        # Ensure current password is not empty
        if not request.form.get("current_password"):
            return apology("must provide current password", 400)

        # Query database for user_id
        rows = db.execute("SELECT hash FROM users WHERE id = :user_id", user_id=session["user_id"])

        # Ensure current password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("current_password")):
            return apology("invalid password", 400)

        # Ensure new password is not empty
        if not request.form.get("new_password"):
            return apology("must provide new password", 400)

        # Ensure new password confirmation is not empty
        elif not request.form.get("new_password_confirmation"):
            return apology("must provide new password confirmation", 400)

        # Ensure new password and confirmation match
        elif request.form.get("new_password") != request.form.get("new_password_confirmation"):
            return apology("new password and confirmation must match", 400)

        # Update database
        hash = generate_password_hash(request.form.get("new_password"))
        rows = db.execute("UPDATE users SET hash = :hash WHERE id = :user_id", user_id=session["user_id"], hash=hash)

        # Show flash
        flash("Password Changed!")
        return redirect("/")

    return render_template("change_password.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("missing symbol")

        if not request.form.get("shares").isdigit():
            return apology("must be a positive integer", 400)

        if not request.form.get("shares"):
            return apology("missing shares")

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("shares must be a positive integer", 400)

        quote = lookup(request.form.get("symbol"))

        if not quote:
            return apology("Invalid symbol")

        row = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        cash = int(row[0]["cash"])

        amount = quote["price"] * float(request.form.get("shares"))

        if cash < amount:
            return apology("not enough cash")

        # add transaction to history
        db.execute("INSERT INTO histories (symbol, shares, price, id) VALUES(:symbol, :shares, :price, :id)",
                   symbol=quote["symbol"], shares=request.form.get("shares"), price=usd(quote["price"]), id=session["user_id"])

        # update cash remaining in database
        db.execute("UPDATE users SET cash = cash - :amount WHERE id=:id", amount=amount, id=session["user_id"])

        # check if user owns a share of symbol already
        user_shares = db.execute("SELECT * FROM portfolio WHERE id=:id AND symbol=:symbol",
                                 id=session["user_id"], symbol=quote["symbol"])

        # if symbol is new
        if not user_shares:
            db.execute("INSERT INTO 'portfolio' ('Symbol','Shares','id','Name','Price') VALUES (:symbol, :shares, :id, :name, :price) ",
                       symbol=quote["symbol"], shares=request.form.get("shares"), id=session["user_id"], name=quote["name"], price=quote["price"])
            flash("Bought")
            return redirect("/")

        # if user already owns some share of the symbol
        else:
            total_shares = user_shares[0]["shares"] + int(request.form.get("shares"))
            db.execute("UPDATE portfolio SET shares=:total_shares WHERE id=:id AND symbol=:symbol",
                       total_shares=total_shares, id=session["user_id"], symbol=quote["symbol"])
            flash("Bought")
            return redirect("/")

    return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    username = request.args.get("username")

    names = db.execute("SELECT username FROM users WHERE username=:username", username=username)
    print(names)
    print(type(names))
    if not names and username:
        return jsonify(True)
    else:
        return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM histories WHERE id=:id", id=session["user_id"])

    return render_template("history.html", rows=rows)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
        quote = lookup(request.form.get("symbol"))
        if quote == None:
            return apology("INVALID SYMBOL")
        name = quote["name"]
        price = quote["price"]
        symbol = quote["symbol"]
        return render_template("temp.html", name=name, price=price, symbol=symbol)
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        hash = generate_password_hash(request.form.get("password"))

        # Ensure confirmation is equal to password
        if not check_password_hash(hash, request.form.get("confirmation")):
            return apology("both passwords should match", 400)
        else:
            rows = db.execute("INSERT into users(username, hash) VALUES(:username, :hash)",
                              username=request.form.get("username"), hash=generate_password_hash(request.form.get("password")))
            if not rows:
                return apology("user already exists", 400)
            session["user_id"] = rows
            flash("Registered")
            return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    table = db.execute("SELECT symbol FROM portfolio WHERE id=:id", id=session["user_id"])
    symbols = []
    for i in range(len(table)):
        symbols.append(table[i]["symbol"])

    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        elif not request.form.get("shares"):
            return apology("missing shares", 400)

        owned_shares = int(db.execute("SELECT shares FROM portfolio where id=:id AND symbol=:symbol",
                                      id=session["user_id"], symbol=request.form.get("symbol"))[0]["shares"])

        if owned_shares < int(request.form.get("shares")):
            return apology("Too many shares", 400)

        updated_shares = owned_shares - int(request.form.get("shares"))

        # update shares in portfolio
        if updated_shares > 0:
            db.execute("UPDATE portfolio SET shares=:shares WHERE id=:id AND symbol=:symbol",
                       shares=updated_shares, id=session["user_id"], symbol=request.form.get("symbol"))

        else:
            db.execute("DELETE FROM portfolio WHERE id=:id AND symbol=:symbol",
                       id=session["user_id"], symbol=request.form.get("symbol"))

        # update cash in database
        quote = lookup(request.form.get("symbol"))
        amount = quote["price"] * float(request.form.get("shares"))
        db.execute("UPDATE users SET cash = cash + :amount WHERE id=:id", amount=amount, id=session["user_id"])

        db.execute("INSERT INTO histories (symbol, shares, price, id) VALUES(:symbol, :shares, :price, :id)",
                   symbol=quote["symbol"], shares=0-int(request.form.get("shares")), price=usd(quote["price"]), id=session["user_id"])

        flash("Sold!")
        return redirect("/")

    else:
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
