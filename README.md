# Безопасная версия приложения

### Инструкция по сборке и запуску приложения

#### Пререквизиты:
```
python
pip
flask
subprocess
```
#### Пример запуска:
1) Переходим в директорию `Safe`.
2) Запускаем `main.py`. 
	`python3 main.py`
3) Переходим в браузере на  `http://127.0.0.1:5000`.


### a. XSS
#### Причина уязвимости
Для исправления уязвимости XSS в коде, необходимо убедиться, что данные пользователя не используются непосредственно и не выводятся на страницу без предварительной обработки. В частности, использование фильтра | safe в Jinja2 может привести к уязвимости, так как оно указывает шаблонизатору не экранировать вывод, что может быть опасно, если данные содержат потенциально вредоносный код.

#### Как исправить
Вот пример того, как можно модифицировать файл `user_profile.html` для предотвращения XSS атак (удалить фильтр | safe):

```
{% extends "base.html" %}

{% block title %}User Profile{% endblock %}

{% block content %}
    <h1>Welcome, {{ user[1] }}!</h1>
    <p>Role: {{ user[3] }}</p>
    <p>Secret: {{ user[-1] }}</p>
    <p>Status: {{ user[4] }}</p>
    <form method="POST" action="{{ url_for('set_status') }}">
        <input type="text" name="status" placeholder="Set your status">
        <button type="submit">Update Status</button>
    </form>
{% endblock %}


```

### b. IDOR
#### Причина Уязвимости
Уязвимость проявляется в функции `user_profile`.
```
def user_profile(username):
    if 'username' in session:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            return render_template('user_profile.html', user=user)
        else:
            abort(404)
    return redirect(url_for('login'))
```
Здесь проверяется только то, что пользователь вошел в систему (`'username' in session`), но не проверяется, соответствует ли запрашиваемый профиль текущему пользователю сессии. Это позволяет любому аутентифицированному пользователю просматривать или изменять информацию других пользователей, просто изменив имя пользователя в URL.

#### Как исправить
Чтобы исправить эту уязвимость, вам нужно убедиться, что пользователь, запрашивающий профиль, имеет право на просмотр этого профиля.

```
def user_profile(username):
    if 'username' in session:
        if session['username'] == username:
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user:
                return render_template('user_profile.html', user=user)
            else:
                abort(404)  # если пользователь не найден
        else:
            abort(403)  # доступ запрещен
    return redirect(url_for('login'))

```
Теперь код проверяет, совпадает ли имя пользователя в сессии с запрашиваемым именем пользователя, и если нет, то возвращает ошибку 403 (доступ запрещен), что предотвращает IDOR. 

### c. SQLI

#### Уязвимость SQLi 
#### Причина уязвимости:
Уязвимость находится в функции login, где пользовательский ввод (имя пользователя и пароль) используется напрямую в SQL запросе без предварительной обработки или использования параметризованных запросов:

```
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
```

#### Как исправить:
В этом коде я использовал параметризованные запросы, которые предотвращают SQL-инъекции, заменяя ввод пользователя плейсхолдерами ?. Это безопасный способ передачи пользовательских данных в SQL-запрос. Обратите внимание, что я также изменил user[1] на user['username'], чтобы код был более читаемым и надежным.

```
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Защищенный SQL запрос с использованием параметризованных запросов
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        db = get_db()
        user = db.execute(query, (username, password)).fetchone()

        # Проверка, был ли найден пользователь
        if user:
            session['username'] = user['username']
            return redirect(url_for('user_profile', username=user['username']))
        else:
            flash('Неверные учетные данные, пожалуйста, попробуйте еще раз.')
            return redirect(url_for('login'))

    return render_template('login.html')
```




### d. OS command injection

#### Причина уязвимости:
Уязвимость возникает из-за того, что пользовательский ввод напрямую включается в команду, которая затем выполняется на сервере. 
```
def ping():
    result = ""
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')

        # выполнение команды ping с пользовательским вводом
        result = os.popen(f'ping -c 4 {ip_address}').read()

    return render_template('ping.html', result=result)
```
Код содержит уязвимость инъекции команды OS, которая позволяет злоумышленникам выполнять произвольные команды на сервере.

#### Как исправить:
Чтобы исправить эту уязвимость, вы должны убедиться, что ввод пользователя надежно проверяется и очищается от специальных символов, которые могут изменить предполагаемую команду. Вот обновленный код:


```
import subprocess
from flask import request, render_template

def ping():
    result = ""
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')

        # Проверка ввода пользователя
        if ip_address and all(c.isalnum() or c in {'.', ':'} for c in ip_address):
            # Безопасное выполнение команды ping с пользовательским вводом
            result = subprocess.run(['ping', '-c', '4', ip_address], capture_output=True, text=True).stdout
        else:
            result = "Некорректный IP-адрес."

    return render_template('ping.html', result=result)

```
В этом коде используется модуль subprocess для безопасного выполнения команды ping, а также добавлена проверка ввода пользователя, чтобы убедиться, что IP-адрес содержит только буквенно-цифровые символы, точки и двоеточия.

### e. Path Traversal
#### Причина уязвимости:
Уязвимость проявляется в функции `load_image`, которая используется для загрузки изображений:
```
def load_image():
    filename = request.args.get('filename')
    if filename:

        filepath = './static/images/' + filename
        return send_file(filepath)
    else:
        return 'Файл не найден', 404
```

#### Как исправить:

Чтобы устранить уязвимость в  коде, следует нормализовать путь к файлу, чтобы избежать возможности обращения к файлам за пределами предполагаемой директории.

```
from werkzeug.utils import secure_filename
from flask import send_from_directory

def load_image():
    filename = request.args.get('filename')
    if filename:
        filename = secure_filename(filename)
        return send_from_directory('./static/images/', filename)
    else:
        return 'Файл не найден', 404

```

В этом примере используется функция secure_filename из модуля werkzeug.utils, которая удаляет любые потенциально опасные символы из имени файла, тем самым предотвращая атаки Path Traversal. Кроме того, функция send_from_directory заменяет прямое соединение путей, что также способствует безопасности.

### f.  Brute force


#### Причины уязвимости:
Уязвимость вызвана тем, что пароль состоит ровно из 5 символов и эти символы цифры. Всего таких вариантов как мы узнали 100000, что не слишком то и сложно перебрать. 

#### Как исправить:
Усиление пароля. Вот пример регулярного выражения, которое требует, чтобы пароль состоял минимум из 8 символов, включая как минимум одну заглавную букву, одну строчную букву, одну цифру и один специальный символ:

Обновленная функция `register()`:
```
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        sha256 = hashlib.sha256()
        data = username + password
        sha256.update(data.encode('utf-8'))
        secret = sha256.hexdigest()

        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
	if not re.fullmatch(password_pattern, password):
    		flash('Пароль должен быть не менее 8 символов и содержать как минимум одну заглавную букву, одну строчную букву, одну цифру и один специальный символ.')
    		return redirect(url_for('register.html'))


        db = get_db()
        db.execute('INSERT INTO users (username, password, role, secret) VALUES (?, ?, ?, ?)',
                   (username, password, 'user', secret))
        db.commit()
        return redirect(url_for('login'))

    return render_template('register.html')
```
Это регулярное выражение гарантирует, что пароль будет достаточно сложным и трудным для взлома методом перебора. 




