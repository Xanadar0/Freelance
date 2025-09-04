import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['DATABASE'] = os.path.join('instance', 'database.db')

# Посты зберігаються в static/posts
POSTS_DIR = os.path.join('static', 'posts')
os.makedirs(POSTS_DIR, exist_ok=True)

# ---------------- Database helpers ----------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE,
            title TEXT,
            profession TEXT,
            content TEXT,
            country TEXT,
            username TEXT
        )
    ''')
    db.commit()

# ---------------- Routes ----------------
@app.route('/')
def index():
    db = get_db()
    posts = db.execute('SELECT * FROM posts ORDER BY id DESC').fetchall()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            error = "Користувач вже існує"
        else:
            hashed = generate_password_hash(password)
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
            db.commit()
            return redirect(url_for('login'))

    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = "Невірний логін або пароль"

    return render_template('login.html', error=error)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    db = get_db()
    username = session['username']

    # Отримуємо всі пости цього користувача
    user_posts = db.execute(
        'SELECT * FROM posts WHERE username = ? ORDER BY id DESC', (username,)
    ).fetchall()

    if request.method == 'POST':
        title = request.form['title']
        profession = request.form['profession']
        content = request.form['content']
        country = request.form['country']

        slug = title.replace(' ', '_')

        db.execute(
            'INSERT INTO posts (slug, title, profession, content, country, username) VALUES (?, ?, ?, ?, ?, ?)',
            (slug, title, profession, content, country, username)
        )
        db.commit()

        # Генерація HTML
        post_html = render_template('post_template.html',
                                    title=title,
                                    profession=profession,
                                    content=content,
                                    country=country,
                                    username=username)
        filepath = os.path.join(POSTS_DIR, f"{slug}.html")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(post_html)

        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', posts=user_posts)

@app.route('/post/<slug>')
def show_post(slug):
    filename = f"{slug}.html"
    full_path = os.path.join(POSTS_DIR, filename)
    if not os.path.exists(full_path):
        return "Post not found", 404
    return redirect(url_for('static', filename=f'posts/{filename}'))

@app.route('/edit/<slug>', methods=['GET', 'POST'])
def edit_post(slug):
    if 'username' not in session:
        return redirect(url_for('login'))

    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE slug = ?', (slug,)).fetchone()
    if not post or post['username'] != session['username']:
        return "Access denied", 403

    if request.method == 'POST':
        title = request.form['title']
        profession = request.form['profession']
        content = request.form['content']
        country = request.form['country']
        new_slug = title.replace(' ', '_')

        # Обробка нового фото
        image_file = request.files.get('image')
        image_filename = post['image']  # залишаємо старе фото за замовчуванням
        if image_file and image_file.filename != '':
            # видаляємо старий файл
            if post['image']:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], post['image'])
                if os.path.exists(old_path):
                    os.remove(old_path)
            # зберігаємо новий файл
            image_filename = f"{new_slug}_{image_file.filename}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)

        # Оновлюємо базу
        db.execute('''
            UPDATE posts 
            SET slug=?, title=?, profession=?, content=?, country=?, image=? 
            WHERE id=?
        ''', (new_slug, title, profession, content, country, image_filename, post['id']))
        db.commit()

        # Перегенерація статичного HTML
        filepath = os.path.join(POSTS_DIR, f"{new_slug}.html")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(render_template('post_template.html',
                                    title=title,
                                    profession=profession,
                                    content=content,
                                    country=country,
                                    username=session['username'],
                                    image=image_filename))

        return redirect(url_for('dashboard'))

    return render_template('edit_post.html', post=post)

app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # максимум 5MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/delete/<slug>', methods=['POST'])
def delete_post(slug):
    if 'username' not in session:
        return redirect(url_for('login'))

    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE slug = ?', (slug,)).fetchone()
    if not post or post['username'] != session['username']:
        return "Access denied", 403

    db.execute('DELETE FROM posts WHERE id=?', (post['id'],))
    db.commit()

    # Видалення HTML файлу
    filepath = os.path.join(POSTS_DIR, f"{slug}.html")
    if os.path.exists(filepath):
        os.remove(filepath)

    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    os.makedirs('instance', exist_ok=True)
    with app.app_context():
        init_db()
    app.run(debug=True)