import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    # Get user id
    user = session["user_id"]

    # Query transactions
    user_transactions = db.execute("""
        SELECT symbol, SUM(shares) AS total_shares
        FROM transactions
        WHERE user_id = ? AND symbol != 'DEPOSIT'
        GROUP BY symbol
        HAVING total_shares > 0
    """, user)

    # Prepare list of holdings
    holdings = []
    total_holdings_value = 0
    for row in user_transactions:
        symbol = row["symbol"]
        shares = row["total_shares"]
        quote = lookup(symbol)
        price = quote["price"]
        name = quote["name"]
        total = shares * price
        total_holdings_value += total

        holdings.append({
            "symbol": symbol,
            "shares": shares,
            "name": name,
            "price": usd(price),
            "total": usd(total)
        })

    # Get current cash
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user)[0]["cash"]

    # Compute grand total (cash + holdings)
    grand_total = user_cash + total_holdings_value

    # Render index.html with all values
    return render_template("index.html", holdings=holdings, cash=usd(user_cash), total_holdings_value=usd(total_holdings_value), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Validate symbol
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)

        quote = lookup(symbol)
        if not quote:
            return apology("must provide valid symbol", 400)

        # Validate shares
        shares = request.form.get("shares")
        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("must provide valid number of shares to buy", 400)

        shares = int(shares)
        price = quote["price"]
        total_cost = shares * price

        # Get user's cash
        user_balance = db.execute("SELECT cash FROM users WHERE id = ?",
                                  session["user_id"])[0]["cash"]

        if total_cost > user_balance:
            return apology("you're broke lol", 400)

        # Update cash
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, session["user_id"])

        # Insert into transactions
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, timestamp) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            session["user_id"], quote["symbol"], shares, price
        )

        flash(
            f"✅ Bought {shares} share{'s' if int(shares) > 1 else ''} of {symbol} at {usd(price)} each — total: {usd(total_cost)}")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Get user id
    user = session["user_id"]

    # Query all transactions
    transactions_history = db.execute(
        "SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp DESC", user)

    # Render history.html with transactions (newest at top)
    return render_template("history.html", transactions=transactions_history)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
        symbol = request.form.get("symbol")
        quote = lookup(symbol)

        if not quote:
            return apology("invalid symbol", 400)

        # Check if the user owns shares of this symbol
        row = db.execute(
            "SELECT SUM(shares) AS total_shares FROM transactions WHERE user_id = ? AND symbol = ?",
            session["user_id"], symbol
        )

        shares_owned = row[0]["total_shares"] or 0

        return render_template(
            "quoted.html",
            name=quote["name"],
            symbol=quote["symbol"],
            price=usd(quote["price"]),
            shares_owned=shares_owned
        )

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        # Ensure password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation must match", 400)

        username = request.form.get("username").strip()
        # Check if username already exists
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username,
                       generate_password_hash(request.form.get("password"), method="pbkdf2:sha256"))
        except ValueError:
            return apology("username already taken", 400)

        # Log the user in
        session["user_id"] = db.execute(
            "SELECT id FROM users WHERE username = ?", request.form.get("username"))[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Get user id
    user = session["user_id"]

    # Query transactions
    user_transactions = db.execute(
        "SELECT symbol, SUM(shares) AS total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0", user)

    # Determine current symbols owned in portfolio
    stocks_holdings = []
    for row in user_transactions:
        symbol = row["symbol"]
        if symbol.upper() == "DEPOSIT":
            continue  # Skip deposits
        shares = row["total_shares"]
        stocks_holdings.append({"symbol": symbol, "shares": shares})

    # Selling shares of selected symbol via form
    if request.method == "POST":
        # Validate symbol
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("missing symbol", 400)

        # Find the holding with the selected symbol
        shares_owned = 0
        for holding in stocks_holdings:
            if holding["symbol"] == symbol:
                shares_owned = holding["shares"]
                break

        if symbol.upper() == "DEPOSIT":
            return apology("can't sell deposits", 400)

        # Validate number of shares format
        shares_to_sell = request.form.get("shares")
        if not shares_to_sell or not shares_to_sell.isdigit() or int(shares_to_sell) <= 0:
            return apology("invalid number of shares", 400)

        # Validate number of shares to sell <= shares owned
        if int(shares_to_sell) > int(shares_owned):
            return apology("too many shares", 400)

        shares_to_sell = int(shares_to_sell)
        quote = lookup(symbol)
        current_price = quote["price"]
        total_transaction = shares_to_sell * current_price

        # Insert into transactions
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, timestamp) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            session["user_id"], quote["symbol"], -shares_to_sell, current_price
        )

        # Update cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",
                   total_transaction, session["user_id"])

        flash(f"💰 Sold {shares_to_sell} share{'s' if int(shares_to_sell) > 1 else ''} of {symbol} at {usd(current_price)} each — total: +{usd(total_transaction)}")
        return redirect("/")

    else:
        # Render sell.html with stocks to pick in the form
        return render_template("sell.html", holdings=stocks_holdings)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current")
        new = request.form.get("new")
        confirmation = request.form.get("confirmation")

        # Validate all fields
        if not current or not new or not confirmation:
            return apology("all fields required", 400)
        if new != confirmation:
            return apology("passwords do not match", 400)

        # Get user's current hashed password
        user = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]
        if not check_password_hash(user["hash"], current):
            return apology("invalid current password", 400)

        # Update password
        new_hash = generate_password_hash(new, method="pbkdf2:sha256")
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"])

        flash("Password changed successfully.")
        return redirect("/")

    else:
        return render_template("change-password.html")


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """Deposit additional cash"""
    if request.method == "POST":
        amount = request.form.get("amount")

        # Validate input
        try:
            amount = float(amount)
            if amount <= 0:
                raise ValueError
        except:
            return apology("Invalid amount", 400)

        # Update user's cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", amount, session["user_id"])

        # Update transactions record
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, timestamp) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            session["user_id"], 'DEPOSIT', 1, amount
        )

        flash(f"💵 Deposited {usd(amount)} to your account.")
        return redirect("/")

    else:
        return render_template("deposit.html")
