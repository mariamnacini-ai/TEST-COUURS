"""
Mini-blog Flask vulnérable - Exercice d'audit de sécurité
==========================================================
ATTENTION : Ce code contient des vulnérabilités INTENTIONNELLES.
Ne JAMAIS déployer en production.

Objectif pédagogique :
  - Identifier toutes les vulnérabilités d'injection
  - Classer chaque finding (type, gravité, ligne)
  - Proposer un correctif pour chacune
  - Rédiger un rapport d'audit synthétique

Lancement :
  pip install flask
  python app.py
  -> http://127.0.0.1:5000
"""

import sqlite3
import hashlib
import os
from dotenv import load_dotenv
from flask import Flask, request, render_template_string, redirect, make_response, g

app = Flask(__name__)
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY must be set in the environment (.env)")
app.secret_key = secret_key
DATABASE = "blog.db"


# ---------------------------------------------------------------------------
# Initialisation de la base
# ---------------------------------------------------------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS posts;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        );
        INSERT INTO users (username, password, role) VALUES
            ('admin', 'e3afed0047b08059d0fada10f400c1e5', 'admin'),
            ('alice', '5f4dcc3b5aa765d61d8327deb882cf99', 'user');
        INSERT INTO posts (author, title, content) VALUES
            ('admin', 'Bienvenue', 'Premier article du blog.'),
            ('alice', 'Mon avis', 'J''aime beaucoup ce blog !');
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Templates (inline pour rester sur un seul fichier)
# ---------------------------------------------------------------------------
PAGE_INDEX = """
<!doctype html>
<html><head><title>Blog</title></head><body>
<h1>Articles du blog</h1>
<form method="get" action="/search">
  <input name="q" placeholder="Rechercher...">
  <button>Chercher</button>
</form>
<p>Bonjour {{ user|safe }} !</p>
<ul>
{% for p in posts %}
  <li><b>{{ p['title']|safe }}</b> par {{ p['author'] }}<br>
      {{ p['content']|safe }}</li>
{% endfor %}
</ul>
<hr>
<a href="/login">Se connecter</a>
</body></html>
"""

PAGE_LOGIN = """
<!doctype html>
<html><body>
<h1>Connexion</h1>
{% if error %}<p style="color:red">{{ error|safe }}</p>{% endif %}
<form method="post">
  <input name="username" placeholder="Utilisateur"><br>
  <input name="password" type="password" placeholder="Mot de passe"><br>
  <button>Entrer</button>
</form>
</body></html>
"""

PAGE_SEARCH = """
<!doctype html>
<html><body>
<h1>Résultats pour : {{ query|safe }}</h1>
<ul>
{% for p in posts %}
  <li>{{ p['title']|safe }} - {{ p['content']|safe }}</li>
{% endfor %}
</ul>
<a href="/">Retour</a>
</body></html>
"""


# ---------------------------------------------------------------------------
# Route 1 : page d'accueil + affichage du pseudo via cookie
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    user = request.cookies.get("username", "invité")
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, author, title, content FROM posts ORDER BY id DESC")
    posts = cur.fetchall()
    return render_template_string(PAGE_INDEX, posts=posts, user=user)


# ---------------------------------------------------------------------------
# Route 2 : connexion utilisateur
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        hashed = hashlib.md5(password.encode()).hexdigest()

        query = "SELECT * FROM users WHERE username = '" + username + \
                "' AND password = '" + hashed + "'"
        try:
            db = get_db()
            cur = db.cursor()
            cur.execute(query)
            row = cur.fetchone()
        except Exception as e:
            return "Erreur SQL : " + str(e) + "<br>Requête : " + query

        if row:
            resp = make_response(redirect("/"))
            resp.set_cookie("username", username)
            resp.set_cookie("role", row["role"])
            return resp
        else:
            error = "Identifiants invalides pour <b>" + username + "</b>"

    return render_template_string(PAGE_LOGIN, error=error)


# ---------------------------------------------------------------------------
# Route 3 : recherche d'articles
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    cur = db.cursor()
    sql = "SELECT id, author, title, content FROM posts " \
          "WHERE title LIKE '%" + q + "%' OR content LIKE '%" + q + "%'"
    try:
        cur.execute(sql)
        posts = cur.fetchall()
    except sqlite3.Error as err:
        return "Erreur lors de la recherche : " + str(err) + \
               "<br><pre>" + sql + "</pre>", 500

    return render_template_string(PAGE_SEARCH, posts=posts, query=q)


# ---------------------------------------------------------------------------
# Lancement
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
