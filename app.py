import math
import os
import re
from calendar import month_name
from collections.abc import Sequence
from datetime import datetime
from functools import wraps
from hashlib import sha256
from secrets import token_hex

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
)
from sqlalchemy import and_, create_engine, func, or_, select
from sqlalchemy.orm import Session

from models import Base, Comment, Conversation, Message, Post, PostLikes, User

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")

engine = create_engine(os.getenv("DB_URL", ""))
Base.metadata.create_all(engine)


def get_diff_time_string(now: datetime, then: datetime) -> str:
    diff = now - then
    seconds = int(diff.total_seconds())
    minutes = seconds // 60
    hours = minutes // 60
    days = hours // 24
    if days > 7:
        return f"{month_name[then.month]} {then.day}, {then.year}"
    if days > 0:
        return f"{days} days ago"
    if hours > 0:
        return f"{hours} hours ago"
    if minutes > 0:
        return f"{minutes} minutes ago"
    if seconds > 0:
        return f"{seconds} seconds ago"
    return "now"


def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if user_id is None:
            return redirect("/login")
        user_stmt = select(User).where(User.id == user_id)
        with Session(engine) as db_session:
            user = db_session.scalars(user_stmt).one_or_none()
        if user is None:
            session.clear()
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def require_signed_out(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if user_id is not None:
            user_stmt = select(User).where(User.id == user_id)
            with Session(engine) as db_session:
                user = db_session.scalars(user_stmt).one_or_none()
                if user is not None:
                    return redirect("/")
        return f(*args, **kwargs)

    return decorated_function


def is_liked_by_user(post: Post, user: User):
    stmt = select(PostLikes).where(PostLikes.user_id == user.id).where(PostLikes.post_id == post.id)
    with Session(engine) as db_session:
        like = db_session.scalars(stmt).one_or_none()
        if like is None:
            return False
    return True


@app.route("/")
@require_login
def index():
    user_id = session.get("user_id")
    user_stmt = select(User).where(User.id == user_id)
    with Session(engine) as db_session:
        user = db_session.scalars(user_stmt).one()

    page = request.args.get("page")
    if page is None:
        page = 1
    else:
        try:
            page = int(page)
        except ValueError:
            page = 1

    limit = 10
    page_index = page - 1
    page_offset = page_index * limit

    num_posts_stmt = select(func.count()).select_from(Post)
    with Session(engine) as db_session:
        num_posts = db_session.scalars(num_posts_stmt).one()

    num_pages = math.ceil(num_posts / limit)
    if num_pages == 0:
        num_pages = 1
    is_first_page = page_index == 0
    is_last_page = page_index == num_pages - 1

    posts_stmt = select(Post).order_by(Post.created_at.desc()).offset(page_offset).limit(limit)

    now = datetime.now()
    with Session(engine) as db_session:
        posts = db_session.scalars(posts_stmt).all()
        return render_template("index.html", posts=posts, get_diff_time_string=get_diff_time_string, now=now, page=page,
                               num_pages=num_pages, is_last_page=is_last_page, is_first_page=is_first_page,
                               next_page=page + 1, prev_page=page - 1, user=user, is_logged_in=True,
                               is_liked_by_user=is_liked_by_user)


def hash_password(password: str, salt: str) -> str:
    salted_password = password + salt
    password_hash = sha256(salted_password.encode()).hexdigest()
    return password_hash


@app.route("/login", methods=["GET", "POST"])
@require_signed_out
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None:
        flash("Username is required")
        return redirect("/login")
    if password is None:
        flash("Password is required")
        return redirect("/login")
    stmt = select(User).where(User.name == username)
    with Session(engine) as db_session:
        user: User | None = db_session.scalars(stmt).one_or_none()
        if user is None:
            flash("User not found")
            return redirect("/login")
    password_hash = hash_password(password, user.password_salt)
    if password_hash == user.password_hash:
        session["user_id"] = user.id
        return redirect("/")
    else:
        flash("Wrong password")
        return redirect("/login")


# Validation Patterns
NAME_REGEX = re.compile(r'^[A-Za-z\s\-]+$')
USERNAME_CHARS_REGEX = re.compile(r'^[A-Za-z0-9_]+$')
SPECIAL_CHAR_REGEX = re.compile(r'[!@#$%^&*(),.?":{}|<>]')


def validate_signup_form(form_data):
    """
    Validates form data and returns errors categorized by field,
    including an explicit error 'type' and formatted 'message'.
    """
    errors = {}

    first_name = form_data.get('first_name', '').strip()
    last_name = form_data.get('last_name', '').strip()
    username = form_data.get('username', '').strip()
    password = form_data.get('password', '')
    confirm_password = form_data.get('confirm_password', '')

    # --- 1. First Name Validation ---
    if not first_name:
        errors['first_name'] = {
            "type": "REQUIRED_FIELD",
            "message": "[REQUIRED_FIELD] First name cannot be empty."
        }
    elif len(first_name) > 30:
        errors['first_name'] = {
            "type": "MAX_LENGTH_EXCEEDED",
            "message": "[MAX_LENGTH_EXCEEDED] First name cannot exceed 30 characters."
        }
    elif not NAME_REGEX.match(first_name):
        errors['first_name'] = {
            "type": "INVALID_CHARACTERS",
            "message": "[INVALID_CHARACTERS] First name can only contain letters, spaces, or hyphens."
        }

    # --- 2. Last Name Validation ---
    if not last_name:
        errors['last_name'] = {
            "type": "REQUIRED_FIELD",
            "message": "[REQUIRED_FIELD] Last name cannot be empty."
        }
    elif len(last_name) > 30:
        errors['last_name'] = {
            "type": "MAX_LENGTH_EXCEEDED",
            "message": "[MAX_LENGTH_EXCEEDED] Last name cannot exceed 30 characters."
        }
    elif not NAME_REGEX.match(last_name):
        errors['last_name'] = {
            "type": "INVALID_CHARACTERS",
            "message": "[INVALID_CHARACTERS] Last name can only contain letters, spaces, or hyphens."
        }

    # --- 3. Username Validation ---
    username_errors = []
    if not username:
        username_errors.append({
            "type": "REQUIRED_FIELD",
            "message": "[REQUIRED_FIELD] Username is required."
        })
    else:
        if len(username) < 3:
            username_errors.append({
                "type": "MIN_LENGTH_NOT_MET",
                "message": "[MIN_LENGTH_NOT_MET] Username must be at least 3 characters."
            })
        elif len(username) > 20:
            username_errors.append({
                "type": "MAX_LENGTH_EXCEEDED",
                "message": "[MAX_LENGTH_EXCEEDED] Username cannot exceed 20 characters."
            })

        if not USERNAME_CHARS_REGEX.match(username):
            username_errors.append({
                "type": "INVALID_CHARACTERS",
                "message": "[INVALID_CHARACTERS] Username can only contain letters, numbers, and underscores."
            })

    if username_errors:
        errors['username'] = username_errors

    # --- 4. Password Validation ---
    password_errors = []
    if not password:
        password_errors.append({
            "type": "REQUIRED_FIELD",
            "message": "[REQUIRED_FIELD] Password is required."
        })
    else:
        if len(password) < 8:
            password_errors.append({
                "type": "PASSWORD_TOO_SHORT",
                "message": "[PASSWORD_TOO_SHORT] Password must be at least 8 characters long."
            })
        if len(password) > 64:
            password_errors.append({
                "type": "MAX_LENGTH_EXCEEDED",
                "message": "[MAX_LENGTH_EXCEEDED] Password cannot exceed 64 characters."
            })
        if not re.search(r'[A-Z]', password):
            password_errors.append({
                "type": "MISSING_UPPERCASE",
                "message": "[MISSING_UPPERCASE] Password requires at least 1 uppercase letter (A-Z)."
            })
        if not re.search(r'[a-z]', password):
            password_errors.append({
                "type": "MISSING_LOWERCASE",
                "message": "[MISSING_LOWERCASE] Password requires at least 1 lowercase letter (a-z)."
            })
        if not re.search(r'[0-9]', password):
            password_errors.append({
                "type": "MISSING_NUMBER",
                "message": "[MISSING_NUMBER] Password requires at least 1 numeric digit (0-9)."
            })
        if not SPECIAL_CHAR_REGEX.search(password):
            password_errors.append({
                "type": "MISSING_SPECIAL_CHAR",
                "message": "[MISSING_SPECIAL_CHAR] Password requires at least 1 special character (!@#$%^&*)."
            })

    if password_errors:
        errors['password'] = password_errors

    # --- 5. Confirm Password Validation ---
    if not confirm_password:
        errors['confirm_password'] = {
            "type": "REQUIRED_FIELD",
            "message": "[REQUIRED_FIELD] Please confirm your password."
        }
    elif password != confirm_password:
        errors['confirm_password'] = {
            "type": "PASSWORD_MISMATCH",
            "message": "[PASSWORD_MISMATCH] Passwords do not match."
        }

    return errors


@app.route("/signup", methods=["GET", "POST"])
@require_signed_out
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    errors = validate_signup_form(request.form)
    if errors:
        for error in errors.values():
            if isinstance(error, list):
                for e in error:
                    flash(e["message"])
            elif isinstance(error, dict):
                flash(error["message"])
        return redirect("/signup")

    username = request.form["username"]
    password = request.form["password"]
    first_name = request.form["first_name"]
    last_name = request.form["last_name"]

    user_stmt = select(User).where(User.name == username)
    with Session(engine) as db_session:
        user = db_session.scalars(user_stmt).one_or_none()
        if user is not None:
            flash(f"{username} is already registered.")
            return redirect("/signup")

        password_salt = token_hex(16)
        password_hash = hash_password(password, password_salt)
        new_user = User(name=username, first_name=first_name, last_name=last_name, password_hash=password_hash,
                        password_salt=password_salt)
        db_session.add(new_user)
        db_session.flush()
        session["user_id"] = new_user.id
        db_session.commit()
        return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.post("/post")
@require_login
def create_post():
    text = request.form["text"]
    user_id = session["user_id"]
    new_post = Post(text=text, user_id=user_id)
    with Session(engine) as db_session:
        db_session.add(new_post)
        db_session.commit()
    return redirect("/")


@app.route("/profile/<int:user_id>")
@require_login
def profile(user_id):
    user_stmt = select(User).where(User.id == user_id)
    with Session(engine) as db_session:
        user = db_session.scalars(user_stmt).one_or_none()
        if user is None:
            abort(404)

    page = request.args.get("page")
    if page is None:
        page = 1
    else:
        try:
            page = int(page)
        except ValueError:
            page = 1

    limit = 10
    page_index = page - 1
    page_offset = page_index * limit

    num_posts_stmt = select(func.count()).select_from(Post).where(Post.user_id == user_id)
    with Session(engine) as db_session:
        num_posts = db_session.scalars(num_posts_stmt).one()

    num_pages = math.ceil(num_posts / limit)
    if num_pages == 0:
        num_pages = 1
    is_first_page = page_index == 0
    is_last_page = page_index == num_pages - 1

    posts_stmt = select(Post).where(Post.user_id == user_id).order_by(Post.created_at.desc()).offset(page_offset).limit(
        limit)

    now = datetime.now()
    with Session(engine) as db_session:
        posts = db_session.scalars(posts_stmt).all()
        return render_template("profile.html", posts=posts, get_diff_time_string=get_diff_time_string, now=now,
                               page=page,
                               num_pages=num_pages, is_last_page=is_last_page, is_first_page=is_first_page,
                               next_page=page + 1, prev_page=page - 1, user=user, is_logged_in=True,
                               is_liked_by_user=is_liked_by_user)


@app.route("/post/<int:post_id>")
@require_login
def display_post(post_id):
    user_id = session["user_id"]
    post_stmt = select(Post).where(Post.id == post_id)
    user_stmt = select(User).where(User.id == user_id)

    page = request.args.get("page")
    if page is None:
        page = 1
    else:
        try:
            page = int(page)
        except ValueError:
            page = 1

    limit = 10
    page_index = page - 1
    page_offset = page_index * limit

    num_comments_stmt = select(func.count()).select_from(Comment).where(Comment.post_id == post_id)
    with Session(engine) as db_session:
        num_comments = db_session.scalars(num_comments_stmt).one()

    num_pages = math.ceil(num_comments / limit)
    if num_pages == 0:
        num_pages = 1
    is_first_page = page_index == 0
    is_last_page = page_index == num_pages - 1

    comments_stmt = select(Comment).where(Comment.post_id == post_id).order_by(Comment.created_at.desc()).offset(
        page_offset).limit(limit)
    with Session(engine) as db_session:
        post = db_session.scalars(post_stmt).one_or_none()
        if post is None:
            abort(404)
        now = datetime.now()
        user = db_session.scalars(user_stmt).one()
        comments = db_session.scalars(comments_stmt).all()
        return render_template("post.html", now=now, post=post, is_logged_in=True,
                               get_diff_time_string=get_diff_time_string, user=user, is_liked_by_user=is_liked_by_user,
                               comments=comments, page=page, num_pages=num_pages, is_first_page=is_first_page,
                               is_last_page=is_last_page, next_page=page + 1, prev_page=page - 1)


@app.route("/like")
@require_login
def like_post():
    post_id = request.args.get("post_id")
    if post_id is None:
        abort(404)
    try:
        post_id = int(post_id)
    except ValueError:
        abort(404)
    post_stmt = select(Post).where(Post.id == post_id)
    with Session(engine) as db_session:
        post = db_session.scalars(post_stmt).one_or_none()
        if post is None:
            abort(404)

        like_stmt = select(PostLikes).where(PostLikes.post_id == post_id).where(PostLikes.user_id == session["user_id"])
        like = db_session.scalars(like_stmt).one_or_none()
        if like is None:
            like = PostLikes(post_id=post_id, user_id=session["user_id"])
            db_session.add(like)
        else:
            db_session.delete(like)
        db_session.commit()
    return redirect(f"/post/{post_id}")


@app.route("/comment", methods=["GET", "POST"])
@require_login
def create_comment():
    post_id = request.form.get("post_id")
    if post_id is None:
        abort(422)
    post_id = int(post_id)
    post_stmt = select(Post).where(Post.id == post_id)
    with Session(engine) as db_session:
        post = db_session.scalars(post_stmt).one_or_none()
        if post is None:
            abort(404)
    text = request.form.get("text")
    if text is None:
        abort(422)
    user_id = session["user_id"]
    comment = Comment(user_id=user_id, post_id=post_id, text=text)
    with Session(engine) as db_session:
        db_session.add(comment)
        db_session.commit()
    return redirect(f"/post/{post_id}")


def get_message_time_text(message_time: datetime):
    now = datetime.now()
    diff = message_time - now
    seconds = int(diff.total_seconds())
    minutes = seconds // 60
    hours = minutes // 60
    days = hours // 24
    if days == 1:
        return "yesterday"
    elif 1 < days < 7:
        return message_time.strftime("%A")
    elif 7 <= days < 30:
        return f"{month_name[message_time.month]} {message_time.day}"
    elif days < 1:
        return message_time.strftime("%I:%M%p")
    return f"{month_name[message_time.month]} {message_time.day}, {message_time.year}"


@app.route("/messages")
@require_login
def get_messages():
    user_id = session["user_id"]
    convos_stmt = select(Conversation).where(
        or_(Conversation.from_user_id == user_id, Conversation.to_user_id == user_id))
    with Session(engine) as db_session:
        convos: Sequence[Conversation] = db_session.scalars(convos_stmt).all()
    convos_with_details = []
    for convo in convos:
        if user_id == convo.from_user_id:
            other_user_id = convo.to_user_id
        else:
            other_user_id = convo.from_user_id

        other_user_stmt = select(User).where(User.id == other_user_id)
        with Session(engine) as db_session:
            other_user = db_session.scalars(other_user_stmt).one_or_none()
            if other_user is None:
                continue

        latest_message_stmt = select(Message).where(Message.convo_id == convo.id).order_by(
            Message.created_at.desc()).limit(1)
        with Session(engine) as db_session:
            latest_message: Message | None = db_session.scalars(latest_message_stmt).one_or_none()

        if latest_message is None:
            formatted_latest_message_date = ""
            latest_message: dict = {"text": ""}
        else:
            latest_message_date = latest_message.created_at
            formatted_latest_message_date = get_message_time_text(latest_message_date)
        convos_with_details.append(
            {"convo": convo, "other_user": other_user, "formatted_latest_message_date": formatted_latest_message_date,
             "latest_message": latest_message})

    convo_id = request.args.get("id")
    active_convo_user = None
    messages = []
    if convo_id is not None:
        try:
            convo_id = int(convo_id)
        except ValueError:
            abort(404)
        convo_stmt = select(Conversation).where(Conversation.id == convo_id)
        with Session(engine) as db_session:
            convo: Conversation | None = db_session.scalars(convo_stmt).one_or_none()
            if convo is None:
                abort(404)
        if user_id == convo.from_user_id:
            other_user_id = convo.to_user_id
        else:
            other_user_id = convo.from_user_id
        other_user_stmt = select(User).where(User.id == other_user_id)
        with Session(engine) as db_session:
            other_user = db_session.scalars(other_user_stmt).one_or_none()
            if other_user is None:
                abort(404)
        active_convo_user = other_user
        messages_stmt = select(Message).where(Message.convo_id == convo_id).order_by(Message.created_at.desc())
        with Session(engine) as db_session:
            messages = db_session.scalars(messages_stmt).all()

    with Session(engine) as db_session:
        return render_template("messages.html", convos_with_details=convos_with_details, is_logged_in=True,
                               convo_id=convo_id, active_convo_user=active_convo_user, messages=messages,
                               get_message_time_text=get_message_time_text)


@app.route("/message", methods=["GET", "POST"])
@require_login
def send_message():
    if request.method == "POST":
        convo_id = request.form.get("convo_id")
        assert convo_id is not None
        convo_id = int(convo_id)
        text = request.form.get("text")
        sender_id = session["user_id"]
        message = Message(convo_id=convo_id, text=text, sender=sender_id)
        with Session(engine) as db_session:
            db_session.add(message)
            db_session.commit()
        return redirect(f"/messages?id={convo_id}")
    elif request.method == "GET":
        user_id = session["user_id"]
        other_user_id = request.args.get("to")
        if other_user_id is None:
            abort(404)
        try:
            other_user_id = int(other_user_id)
        except ValueError:
            abort(404)
        with Session(engine) as db_session:
            other_user_stmt = select(User).where(User.id == other_user_id)
            other_user = db_session.scalars(other_user_stmt).one_or_none()
            if other_user is None:
                abort(404)
        convo_stmt = select(Conversation).where(
            or_(and_(Conversation.from_user_id == user_id, Conversation.to_user_id == other_user_id),
                and_(Conversation.to_user_id == user_id, Conversation.from_user_id == other_user_id)))
        with Session(engine) as db_session:
            convo = db_session.scalars(convo_stmt).one_or_none()

        if convo is None:
            convo = Conversation(from_user_id=user_id, to_user_id=other_user_id)

        with Session(engine) as db_session:
            db_session.add(convo)
            db_session.commit()

            return redirect(f"/messages?id={convo.id}")
