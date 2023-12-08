import hashlib
import re
from flask import Flask, render_template, request, redirect, url_for, session, g, abort, send_file, flash
import sqlite3
import os



app = Flask(__name__)
DATABASE = 'database.db'

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'database.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/logout')
def logout():
    # Удаляем пользователя из сессии
    session.pop('username', None)
    # Перенаправляем на главную страницу или страницу входа
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        sha256 = hashlib.sha256()
        data = username + password
        sha256.update(data.encode('utf-8'))
        secret = sha256.hexdigest()

        # Проверка пароля на соответствие требованиям
        if not re.fullmatch(r'\d{5}', password):
            flash('Пароль должен состоять из 5 цифр.')
            return redirect(url_for('register'))


        db = get_db()
        db.execute('INSERT INTO users (username, password, role, secret) VALUES (?, ?, ?, ?)',
                   (username, password, 'user', secret))
        db.commit()
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Уязвимый SQL запрос
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        db = get_db()
        user = db.execute(query).fetchone()

        # Проверка, был ли найден пользователь
        if user:
            session['username'] = user[1]
            return redirect(url_for('user_profile', username=user[1]))
        else:
            flash('Invalid credentials, please try again.')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/user/<username>')
def user_profile(username):
    if 'username' in session:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            return render_template('user_profile.html', user=user)
        else:
            abort(404)  # если пользователь не найден
    return redirect(url_for('login'))


@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = ""
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')

        # выполнение команды ping с пользовательским вводом
        result = os.popen(f'ping -c 4 {ip_address}').read()

    return render_template('ping.html', result=result)


@app.route('/loadImage')
def load_image():
    filename = request.args.get('filename')
    if filename:

        filepath = './static/images/' + filename
        return send_file(filepath)
    else:
        return 'Файл не найден', 404


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/set_status', methods=['POST'])
def set_status():
    if 'username' not in session:
        return redirect(url_for('login'))

    status = request.form.get('status', '')
    username = session['username']

    db = get_db()
    db.execute('UPDATE users SET status = ? WHERE username = ?', (status, username))
    db.commit()

    return redirect(url_for('user_profile', username=username))


@app.route('/')
def index():
    category = request.args.get('category')
    db = get_db()

    if category:
        # Выбираем изображения по категории
        query = f"SELECT * FROM mr_robot WHERE category = '{category}'"
        images = db.execute(query).fetchall()
    else:

        images = db.execute('SELECT * FROM mr_robot LIMIT 4').fetchall()

    return render_template('index.html', images=images, selected_category=category)


if __name__ == '__main__':
    app.run()
