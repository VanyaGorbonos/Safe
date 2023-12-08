import sqlite3


conn = sqlite3.connect('database.db')

# Удаление существующих таблиц 
conn.execute('DROP TABLE IF EXISTS users')
conn.execute('DROP TABLE IF EXISTS mr_robot')


conn.execute('''
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT,
    status TEXT,
    secret TEXT
);
''')


users = [
    ('admin', '00101', 'admin', 'cool status', 'c92c0babdc764d8674bcea14a55d867d'),
    ('user1', '32411', 'user', 'cool status', 'ef39fbf69170b58787ce4e574db9d842'),
    ('user2', '56321', 'user', 'cool status', '3ab1faad513e753501264a716612ba06'),
    ('user3', '51331', 'user', 'cool status', '3ab1faad513e753501264a716622ba06'),

]

conn.executemany('INSERT INTO users (username, password, role, status, secret) VALUES (?, ?, ?, ?, ?)', users)


conn.execute('''
CREATE TABLE mr_robot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    image_path TEXT NOT NULL,
    description TEXT
);
''')


Mr_Robot = [
    ('hero', 'hero1', 'hero1.jpg', 'description1'),
    ('hero', 'hero2', 'hero2.jpg', 'description2'),
    ('hero', 'hero3', 'hero3.jpg', 'description3'),
    ('hero', 'hero4', 'hero4.jpg', 'description4'),
    ('plot', 'plot1', 'plot1.jpg', 'plot description1'),
    ('plot', 'plot2', 'plot2.webp', 'plot description2'),

    ('episode', 'episode1', 'episode1.jpg', 'episode description1'),
    ('episode', 'episode2', 'episode2.webp', 'episode description2'),

]

conn.executemany('INSERT INTO mr_robot (category, name, image_path, description) VALUES (?, ?, ?, ?)', Mr_Robot)


conn.commit()
conn.close()

