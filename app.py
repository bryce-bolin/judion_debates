from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
import random, string, time, os
from dotenv import load_dotenv
from openai import OpenAI
from markupsafe import Markup
import markdown2
from threading import Thread
from flask_socketio import SocketIO, join_room, leave_room

# ----------------- Global Storage (ephemeral) -----------------
GLOBAL_DEBATES = {}      # { CODE: {type, title, description, code} }
GLOBAL_MESSAGES = {}     # { "debate:CODE" | "solo:SID": [ {user, role, text, ts}, ... ] }

# ----------------- Env & OpenAI -----------------
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = None
if OPENAI_API_KEY:
    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
        print("OpenAI client initialized.")
    except Exception as e:
        print(f"WARNING: Failed to init OpenAI client: {e}")
else:
    print("WARNING: OPENAI_API_KEY not set. AI features will be disabled.")

# ----------------- Flask / DB / Login -----------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or "change_me_for_production"

socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///judion.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id        = db.Column(db.Integer, primary_key=True)
    email     = db.Column(db.String(120), unique=True, nullable=False)
    password  = db.Column(db.String(200), nullable=False)
    username  = db.Column(db.String(80), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------- Jinja filter -----------------
@app.template_filter("markdown")
def markdown_filter(text):
    return Markup(markdown2.markdown(text or ""))

# ---------- Helpers ----------
def generate_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

@app.context_processor
def inject_chats():
    # We keep your existing sidebar list in session for now
    return {"chats": session.get("chats", [])}

# ---------- Background workers (GLOBAL_* only) ----------
def _bg_ai_reply_for_solo(sid: str):
    key = f"solo:{sid}"
    msgs = GLOBAL_MESSAGES.get(key, [])
    history = [{"role": "system", "content": "You are Judion, a helpful AI assistant."}]
    for m in msgs:
        history.append({"role": m["role"], "content": m["text"]})
    try:
        if not client:
            raise RuntimeError("No OpenAI client configured.")
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=history,
            max_completion_tokens=300
        )
        ai_text = resp.choices[0].message.content.strip()
    except Exception as e:
        ai_text = f"(Error: {e})"
    msgs.append({"user": "AI", "role": "assistant", "text": ai_text, "ts": int(time.time())})
    GLOBAL_MESSAGES[key] = msgs
    socketio.emit("new_message", msgs[-1], room=key)

def _bg_judge_reply_for_debate(code: str):
    key = f"debate:{code}"
    msgs = GLOBAL_MESSAGES.get(key, [])
    history = [{
        "role": "system",
        "content": (
            "You are Judion, a **neutral debate judge**. "
            "Read the arguments from all participants carefully. "
            "Your job is to:\n"
            "1. Summarize key points from each side 📝\n"
            "2. Evaluate strengths & weaknesses ⚖️\n"
            "3. Deliver a fair verdict 🎯\n\n"
            "Always format your reply with Markdown (headings, bullet points, emojis)."
        )
    }]
    for m in msgs:
        role = "user" if m["role"] == "user" else "assistant"
        history.append({"role": role, "content": f"{m['user']}: {m['text']}"})
    try:
        if not client:
            raise RuntimeError("No OpenAI client configured.")
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=history,
            max_completion_tokens=400
        )
        ai_text = resp.choices[0].message.content.strip()
    except Exception as e:
        ai_text = f"(Error from Judge: {e})"
    msgs.append({"user": "Judge", "role": "assistant", "text": ai_text, "ts": int(time.time())})
    GLOBAL_MESSAGES[key] = msgs
    socketio.emit("new_message", msgs[-1], room=key)

# ===================== AUTH (Step 5) =====================

@app.route("/", methods=["GET"])
def root():
    # Redirect root to login or main depending on auth state
    if current_user.is_authenticated:
        return redirect(url_for("main"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    # Real email+password login
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        user = User.query.filter_by(email=email).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

        login_user(user, remember=True)
        # Make sure the user has a personal sidebar list
        session.setdefault("chats", [])
        return redirect(url_for("main"))

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not email or not username or not password:
            flash("All fields are required.", "warning")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("That email is already registered.", "warning")
            return redirect(url_for("signup"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(email=email, username=username, password=hashed_pw)
        db.session.add(user)
        db.session.commit()

        login_user(user, remember=True)
        session.setdefault("chats", [])
        return redirect(url_for("main"))

    return render_template("signup.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    # Clear only the sidebar list; your app state is otherwise ephemeral
    session.pop("chats", None)
    return redirect(url_for("login"))

# ===================== APP ROUTES (Step 7 + Step 8) =====================

@app.route("/main")
@login_required
def main():
    return render_template("main.html")

# ----- Create Debate (registers globally) -----
@app.route("/create/debate", methods=["POST"])
@login_required
def create_debate():
    title = (request.form.get("title") or "Untitled Debate").strip()
    description = (request.form.get("description") or "").strip()
    code = (request.form.get("code") or generate_code()).strip().upper()

    chat = {"type": "debate", "title": title, "description": description, "code": code}

    GLOBAL_DEBATES[code] = chat
    GLOBAL_MESSAGES.setdefault(f"debate:{code}", [])

    session.setdefault("chats", [])
    session["chats"] = [c for c in session["chats"]
                        if not (c.get("type") == "debate" and c.get("code") == code)]
    session["chats"].insert(0, chat)
    session.modified = True

        # If AJAX request, don't redirect; keep the page in place
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return ("", 204)
    return redirect(url_for("debate_room", code=code))

# ----- Join Debate by code -----
@app.route("/join/debate", methods=["POST"])
@login_required
def join_debate():
    code = (request.form.get("code") or "").strip().upper()
    room = GLOBAL_DEBATES.get(code)
    if not room:
        return redirect(url_for("main"))

    session.setdefault("chats", [])
    if not any(c.get("type") == "debate" and c.get("code") == code for c in session["chats"]):
        session["chats"].insert(0, room)
        session.modified = True

    return redirect(url_for("debate_room", code=code))

@socketio.on("join")
def on_join(data):
    """data = {'room': 'debate:CODE' or 'solo:SID'}"""
    room = data.get("room")
    if room:
        join_room(room)

@socketio.on("leave")
def on_leave(data):
    room = data.get("room")
    if room:
        leave_room(room)


# ----- Debate Room -----
@app.route("/room/<code>")
@login_required
def debate_room(code):
    room = GLOBAL_DEBATES.get(code)
    if not room:
        abort(404)
    key = f"debate:{code}"
    GLOBAL_MESSAGES.setdefault(key, [])
    return render_template("debate_room.html", room=room, messages=GLOBAL_MESSAGES[key])

@app.post("/room/<code>/message")
@login_required
def debate_message(code):
    if code not in GLOBAL_DEBATES:
        abort(404)
    text = (request.form.get("text") or "").strip()
    if text:
        key = f"debate:{code}"
        GLOBAL_MESSAGES.setdefault(key, [])
        new_msg = {
            "user": current_user.username,  # Step 8: username from login
            "role": "user",
            "text": text,
            "ts": int(time.time())
        }
        GLOBAL_MESSAGES[key].append(new_msg)
        socketio.emit("new_message", new_msg, room=key)
        socketio.start_background_task(_bg_judge_reply_for_debate, code)
    return redirect(url_for("debate_room", code=code))

# ----- Create / Solo Room -----
@app.route("/create/solo", methods=["POST"])
@login_required
def create_solo():
    sid = generate_code()
    chat = {"type": "solo", "sid": sid, "title": "Solo Chat", "description": ""}
    session.setdefault("chats", [])
    session["chats"].insert(0, chat)
    session.modified = True
    GLOBAL_MESSAGES.setdefault(f"solo:{sid}", [])
    return redirect(url_for("solo_room", sid=sid))

@app.route("/solo/<sid>")
@login_required
def solo_room(sid):
    chats = session.get("chats", [])
    room = next((c for c in chats if c.get("type") == "solo" and c.get("sid") == sid), None)
    if not room:
        abort(404)
    key = f"solo:{sid}"
    GLOBAL_MESSAGES.setdefault(key, [])
    return render_template("solo_room.html", room=room, messages=GLOBAL_MESSAGES[key])

@app.post("/solo/<sid>/message")
@login_required
def solo_message(sid):
    text = (request.form.get("text") or "").strip()
    if text:
        key = f"solo:{sid}"
        GLOBAL_MESSAGES.setdefault(key, [])
        GLOBAL_MESSAGES[key].append({
            "user": current_user.username,  # Step 8: username from login
            "role": "user",
            "text": text,
            "ts": int(time.time())
        })
        socketio.emit("new_message", GLOBAL_MESSAGES[key][-1], room=key)
    socketio.start_background_task(_bg_ai_reply_for_solo, sid)
        # If AJAX request, don't redirect; keep the page in place
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return ("", 204)
    return redirect(url_for("solo_room", sid=sid))

# ----- Delete chat -----
@app.post("/delete/<chat_id>")
@login_required
def delete_chat(chat_id):
    chats = session.get("chats", [])
    found_idx, found_chat = None, None
    for i, c in enumerate(chats):
        if (c.get("type") == "debate" and c.get("code") == chat_id) or (c.get("type") == "solo" and c.get("sid") == chat_id):
            found_idx, found_chat = i, c
            break
    if found_idx is not None:
        chats.pop(found_idx)
        session["chats"] = chats
        if found_chat.get("type") == "debate":
            code = found_chat.get("code")
            GLOBAL_DEBATES.pop(code, None)
            GLOBAL_MESSAGES.pop(f"debate:{code}", None)
        else:
            sid = found_chat.get("sid")
            GLOBAL_MESSAGES.pop(f"solo:{sid}", None)
        session.modified = True
    return redirect(url_for("main"))

# ----- Local dev entry (Render uses gunicorn) -----
if __name__ == "__main__":
    socketio.run(
        app,
        debug=True,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
    )