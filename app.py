import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
import random, string, time, os, re
from dotenv import load_dotenv
from openai import OpenAI
from markupsafe import Markup

import markdown2
import bleach

from flask_socketio import SocketIO, join_room, leave_room

import sys

# Hard kill if not Python 3.11.*
if not (sys.version_info.major == 3 and sys.version_info.minor == 11):
    raise RuntimeError(
        f"Python {sys.version.split()[0]} is not supported. "
        "This app requires Python 3.11 for eventlet / Flask-SocketIO."
    )

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

def _markdown_to_openai_content(text: str):
    content = []
    pattern = re.compile(r'!\[[^\]]*\]\(([^)]+)\)')
    last_idx = 0
    source = text or ""
    for match in pattern.finditer(source):
        start, end = match.span()
        if start > last_idx:
            chunk = source[last_idx:start].strip()
            if chunk:
                content.append({"type": "text", "text": chunk})
        image_url = match.group(1).strip()
        if image_url:
            content.append({
                "type": "image_url",
                "image_url": {"url": image_url}
            })
        last_idx = end
    trailing = source[last_idx:].strip()
    if trailing:
        content.append({"type": "text", "text": trailing})
    if not content:
        content.append({"type": "text", "text": source})
    return content

def _response_text(message_content):
    if isinstance(message_content, str):
        return message_content.strip()
    parts = []
    for part in message_content or []:
        if part.get("type") == "text" and part.get("text"):
            parts.append(part["text"])
    return "\n\n".join(parts).strip()

def _call_gpt(messages):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=messages
    )
    return _response_text(resp.choices[0].message.content)

# ---------- Background workers (GLOBAL_* only) ----------
def _bg_ai_reply_for_solo(sid: str):
    key = f"solo:{sid}"
    msgs = GLOBAL_MESSAGES.get(key, [])
    history = [{
        "role": "system",
        "content": [{
            "type": "text",
            "text": "You are Judion, a helpful AI assistant. Respond using Markdown and wrap any code in fenced code blocks."
        }]
    }]
    for m in msgs:
        history.append({"role": m["role"], "content": _markdown_to_openai_content(m["text"])})
    try:
        if not client:
            raise RuntimeError("No OpenAI client configured.")
        ai_text = _call_gpt(history)
    except Exception as e:
        ai_text = f"(Error: {e})"
    msgs.append({"user": "AI", "role": "assistant", "text": ai_text, "ts": int(time.time())})
    GLOBAL_MESSAGES[key] = msgs
    socketio.emit("new_message", msgs[-1], room=key)

def _bg_judge_reply_for_debate(code: str):
    key = f"debate:{code}"
    msgs = GLOBAL_MESSAGES.get(key, [])
    participants = sorted(list(GLOBAL_DEBATES.get(code, {}).get("participants", [])))
    history = [{
        "role": "system",
        "content": [{
            "type": "text",
            "text": (
                "You are Judion, a **neutral debate judge**. "
                "Read the arguments from all participants carefully. "
                "Your job is to:\n"
                "1. Summarize key points from each side 📝\n"
                "2. Evaluate strengths & weaknesses ⚖️\n"
                "3. Deliver a fair verdict 🎯\n\n"
                "Always format your reply with Markdown (headings, bullet points, emojis) and wrap any code in fenced code blocks. "
                "Keep the verdict very short (ideally 2-3 sentences) using simple, clear language while preserving key details. "
                f"You may reference participants using @username. Participants: {', '.join(participants) if participants else 'N/A'}."
            )
        }]
    }]
    for m in msgs:
        role = "user" if m["role"] == "user" else "assistant"
        history.append({"role": role, "content": _markdown_to_openai_content(m["text"])})
    try:
        if not client:
            raise RuntimeError("No OpenAI client configured.")
        ai_text = _call_gpt(history)
        if ai_text.lower().startswith("judge:"):
            ai_text = ai_text.split(":", 1)[1].lstrip()
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

    chat_meta = {
        "type": "debate",
        "title": title,
        "description": description,
        "code": code,
    }

    GLOBAL_DEBATES[code] = {
        **chat_meta,
        "phase": "claim",
        "claims_submitted": set(),
        "counter_submitted": set(),
        "participants": {current_user.username},
    }
    GLOBAL_MESSAGES.setdefault(f"debate:{code}", [])

    session.setdefault("chats", [])
    session["chats"] = [c for c in session["chats"]
                        if not (c.get("type") == "debate" and c.get("code") == code)]
    session["chats"].insert(0, chat_meta)
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
        session["chats"].insert(0, {
            "type": "debate",
            "title": room.get("title"),
            "description": room.get("description", ""),
            "code": code,
        })
        session.modified = True
    if room.get("phase", "claim") == "claim":
        room.setdefault("participants", set()).add(current_user.username)

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
    phase = room.setdefault("phase", "claim")
    participants = room.setdefault("participants", set())
    claims = room.setdefault("claims_submitted", set())
    counter = room.setdefault("counter_submitted", set())
    user = current_user.username
    has_claim = user in claims
    has_counter = user in counter
    can_submit = True
    status_msg = ""
    phase_label = "Claim phase" if phase == "claim" else ("Counterclaim phase" if phase == "counterclaim" else "Debate finished")

    if phase == "claim" and has_claim:
        can_submit = False
        status_msg = "Waiting for other participants to submit their claims."
    elif phase == "counterclaim":
        if has_counter:
            can_submit = False
            status_msg = "Waiting for other participants to submit their counterclaims."
    elif phase == "finished":
        can_submit = False
        status_msg = "Debate finished. Awaiting judge verdict."

    return render_template(
        "debate_room.html",
        room=room,
        messages=GLOBAL_MESSAGES[key],
        phase=phase,
        has_claim=has_claim,
        has_counter=has_counter,
        can_submit=can_submit,
        phase_label=phase_label,
        status_message=status_msg,
    )

@app.post("/room/<code>/message")
@login_required
def debate_message(code):
    room = GLOBAL_DEBATES.get(code)
    if not room:
        abort(404)

    def phase_error(message):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return (message, 409)
        flash(message, "warning")
        return redirect(url_for("debate_room", code=code))

    text = (request.form.get("text") or "").strip()
    if not text:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return ("", 204)
        return redirect(url_for("debate_room", code=code))

    key = f"debate:{code}"
    GLOBAL_MESSAGES.setdefault(key, [])

    phase = room.setdefault("phase", "claim")
    participants = room.setdefault("participants", set())
    claims = room.setdefault("claims_submitted", set())
    counter = room.setdefault("counter_submitted", set())
    user = current_user.username
    if user not in participants:
        if phase == "claim":
            participants.add(user)
        else:
            return phase_error("This debate round is already in progress.")

    if phase == "finished":
        return phase_error("Debate is finished. Await the judge's verdict.")
    if phase == "claim" and user in claims:
        return phase_error("You have already submitted your claim.")
    if phase == "counterclaim" and user in counter:
        return phase_error("You have already submitted your counterclaim.")

    new_msg = {
        "user": user,
        "role": "user",
        "text": text,
        "ts": int(time.time())
    }
    GLOBAL_MESSAGES[key].append(new_msg)
    socketio.emit("new_message", new_msg, room=key)

    phase_changed = False
    if phase == "claim":
        claims.add(user)
        if len(claims) >= len(participants):
            room["phase"] = "counterclaim"
            room["counter_submitted"] = set()
            phase_changed = True
            announcement = {
                "user": "System",
                "role": "assistant",
                "text": (
                    "Great job on the claims! Counterclaim phase begins now. "
                    "Use @username to directly respond to someone you disagree with."
                ),
                "ts": int(time.time())
            }
            GLOBAL_MESSAGES[key].append(announcement)
            socketio.emit("new_message", announcement, room=key)
    elif phase == "counterclaim":
        counter.add(user)
        if len(counter) >= len(participants):
            room["phase"] = "finished"
            phase_changed = True
            eventlet.spawn_n(_bg_judge_reply_for_debate, code)

    if phase_changed:
        socketio.emit(
            "phase_update",
            {
                "phase": room["phase"],
                "participants": sorted(list(participants))
            },
            room=key
        )

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return ("", 204)
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
    key = f"solo:{sid}"

    if text:
        GLOBAL_MESSAGES.setdefault(key, [])
        GLOBAL_MESSAGES[key].append({
            "user": current_user.username,
            "role": "user",
            "text": text,
            "ts": int(time.time())
        })
        socketio.emit("new_message", GLOBAL_MESSAGES[key][-1], room=key)

        # spawn the AI reply using eventlet instead of Thread
        eventlet.spawn_n(_bg_ai_reply_for_solo, sid)

    # If this was an AJAX call, we return 204 instead of redirecting
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return ("", 204)

    # Fallback for normal form POST
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

@app.post("/rename/<chat_id>")
@login_required
def rename_chat(chat_id):
    new_title = (request.form.get("title") or "").strip()
    if not new_title:
        return ("", 204)

    chats = session.get("chats", [])
    updated = False
    chat_type = request.form.get("type")

    for chat in chats:
        if chat_type == "debate" and chat.get("type") == "debate" and chat.get("code") == chat_id:
            chat["title"] = new_title
            GLOBAL_DEBATES.get(chat_id, {}).update({"title": new_title})
            updated = True
            break
        if chat_type == "solo" and chat.get("type") == "solo" and chat.get("sid") == chat_id:
            chat["title"] = new_title
            updated = True
            break

    if updated:
        session["chats"] = chats
        session.modified = True
    return ("", 204)

@app.post("/api/generate_image")
@login_required
def generate_image():
    data = request.get_json(silent=True) or {}
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        abort(400)
    if not client:
        abort(503)
    try:
        resp = client.images.generate(
            model="gpt-image-1-mini",
            prompt=prompt,
            size="1024x1024"
        )
        image_b64 = resp.data[0].b64_json
        data_url = f"data:image/png;base64,{image_b64}"
        return jsonify({"image": data_url})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

# ----- Local dev entry (Render uses gunicorn) -----
if __name__ == "__main__":
    socketio.run(
        app,
        debug=True,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5002)),
        use_reloader=False,
    )
# AI + Markdown + Bleach setup

# Allow Markdown2 features like fenced code blocks, tables, etc.
_MD_EXTRAS = [
    "fenced-code-blocks", "tables", "strike", "code-friendly",
    "cuddled-lists", "task_list", "spoiler"
]

# Restrictive, safe HTML allowlist (expand if you need more tags)
_ALLOWED_TAGS = [
    "p","br","hr","pre","code","blockquote","ul","ol","li","strong","em","del",
    "h1","h2","h3","h4","h5","h6","table","thead","tbody","tr","th","td","span",
    "a","img"
]
_ALLOWED_ATTRS = {
    "a": ["href","title","target","rel"],
    "code": ["class"],
    "span": ["class"],
    "img": ["src","alt","title"]
}
_ALLOWED_PROTOCOLS = ["http", "https", "mailto", "data"]
# Optional: ensure links open safely
def _link_rel_target(attrs, new=False):
    href = attrs.get("href", "")
    if href.startswith("javascript:"):
        attrs["href"] = "#"
    attrs["target"] = "_blank"
    attrs["rel"] = "noopener noreferrer"
    return attrs

def render_markdown(md_text: str) -> str:
    """
    Convert Markdown to HTML (with fenced code blocks) and sanitize it.
    Returns safe HTML ready to insert into templates.
    """
    md_html = markdown2.markdown(md_text or "", extras=_MD_EXTRAS)

    # Sanitize (prevents XSS) but keep our code/headers/etc.
    clean = bleach.clean(
        md_html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=_ALLOWED_PROTOCOLS,
        strip=True,
    )
    # Linkify after clean so URLs become <a> tags, then re-sanitize a tiny bit
    linkified = bleach.linkify(clean, callbacks=[bleach.linkifier.Callback(_link_rel_target)])

    return linkified

# Jinja filter (replace your existing simple one)
from markupsafe import Markup

@app.template_filter("markdown")
def markdown_filter(text):
    return Markup(render_markdown(text))
# End Markdown + Bleach setup   
