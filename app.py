from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from cs50 import SQL

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///hack.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        if session.get("user_id"):
            username = db.execute(
                "SELECT  username FROM users WHERE id = ?", session["user_id"]
            )[0]["username"]
            time = db.execute(
                "SELECT  time FROM users WHERE id = ?", session["user_id"]
            )[0]["time"]
            ftime = db.execute(
                "SELECT  ftime FROM users WHERE id = ?", session["user_id"]
            )[0]["ftime"]
            ctime = db.execute(
                "SELECT  ctime FROM users WHERE id = ?", session["user_id"]
            )[0]["ctime"]
            return render_template(
                "index.html", ftime=ftime, username=username, time=time, ctime=ctime
            )
        else:
            return render_template("index.html", ftime=25, ctime=5)
    else:
        if session.get("user_id"):
            db.execute(
                "UPDATE users SET time = time + 0.5 WHERE id = ?", session["user_id"]
            )


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        sftime = request.form.get("ftime")
        sctime = request.form.get("ctime")
        try:
            sftime = int(sftime)
            sctime = int(sctime)
        except (ValueError, TypeError):
            ftime = db.execute(
                "SELECT  ftime FROM users WHERE id = ?", session["user_id"]
            )[0]["ftime"]
            ctime = db.execute(
                "SELECT  ctime FROM users WHERE id = ?", session["user_id"]
            )[0]["ctime"]
            return render_template("settings.html", ftime=ftime, ctime=ctime)
        if sftime < 1 and sctime < 1:
            ftime = db.execute(
                "SELECT  ftime FROM users WHERE id = ?", session["user_id"]
            )[0]["ftime"]
            ctime = db.execute(
                "SELECT  ctime FROM users WHERE id = ?", session["user_id"]
            )[0]["ctime"]
            return render_template("settings.html", ftime=ftime, ctime=ctime)
        db.execute(
            "UPDATE users SET ftime = ?, ctime = ? WHERE id = ?",
            sftime,
            sctime,
            session["user_id"],
        )
        return redirect("/")
    else:
        ftime = db.execute("SELECT  ftime FROM users WHERE id = ?", session["user_id"])[
            0
        ]["ftime"]
        ctime = db.execute("SELECT  ctime FROM users WHERE id = ?", session["user_id"])[
            0
        ]["ctime"]
        return render_template("settings.html", ftime=ftime, ctime=ctime)


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return render_template("login.html", info="username invalid")
        elif not request.form.get("password"):
            return render_template("login.html", info="password invalid")
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return render_template("login.html", info="username/password incorrect")
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        passw = request.form.get("password")
        rpassw = request.form.get("cpassword")
        if (
            not username
            or len(db.execute("SELECT * FROM users WHERE username = ?", username)) != 0
        ):
            return render_template("register.html", info="username taken/invalid")
        if passw != rpassw or not passw:
            return render_template(
                "register.html", info="password invalid / password do not match"
            )
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            username,
            generate_password_hash(passw),
        )
    return redirect("/login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/leaderboard")
def leaderboard():
    leaderboard_data = db.execute("SELECT username, time FROM users ORDER BY time DESC LIMIT 5")
    return render_template("leaderboard.html", leaderboard=leaderboard_data)

if __name__ == '__main__':
    app.run(debug=True)