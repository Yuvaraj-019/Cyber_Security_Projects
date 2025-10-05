# vuln_login.py
# Minimal vulnerable login app for local testing only.
# DO NOT expose this to the public internet. For lab use only.

from flask import Flask, request, redirect, render_template_string, url_for

app = Flask(__name__)

# Hardcoded credentials for demo (safe only for local testing)
VALID = {"admin": "admin", "test": "123456"}

LOGIN_PAGE = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Demo Login</title></head>
<body>
  <h2>Demo Login</h2>
  <form method="post" action="/login">
    <label>Username: <input name="username" autocomplete="off"></label><br><br>
    <label>Password: <input name="password" type="password" autocomplete="off"></label><br><br>
    <button type="submit">Login</button>
  </form>
  {% if error %}
    <p style="color:red">{{ error }}</p>
  {% endif %}
</body>
</html>
"""

DASHBOARD = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Dashboard</title></head>
<body>
  <h2>Welcome, {{ user }}!</h2>
  <p>This is a demo dashboard.</p>
  <p><a href="/logout">Logout</a></p>
</body>
</html>
"""

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u in VALID and VALID[u] == p:
            # Successful login -> redirect to dashboard (302)
            return redirect(url_for("dashboard", user=u))
        else:
            return render_template_string(LOGIN_PAGE, error="Invalid credentials")
    return render_template_string(LOGIN_PAGE)

@app.route("/dashboard")
def dashboard():
    user = request.args.get("user", "user")
    return render_template_string(DASHBOARD, user=user)

@app.route("/logout")
def logout():
    return "Logged out (demo)."

if __name__ == "__main__":
    # Default binds to localhost only (safe). Use 0.0.0.0 only if you understand the risks.
    app.run(host="127.0.0.1", port=5000, debug=False)
