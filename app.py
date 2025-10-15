from flask import Flask, render_template, request, redirect, url_for, session, abort
import random, string, time, os
from dotenv import load_dotenv
from openai import OpenAI
from markupsafe import Markup
import markdown2
from threading import Thread

# ----------------- Global Storage (ephemeral) -----------------
# Visible to ALL users on this server instance
GLOBAL_DEBATES = {}      # { CODE: {type, title, description, code} }
GLOBAL_MESSAGES = {}     # { "debate:CODE" | "solo:SID": [ {user, role, text, ts}, ... ] }

# ----------------- Env & OpenAI -----------------
load_dotenv()  # local dev; on Render you set env vars in dashboard

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

# ----------------- Flask -----------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or "change_me_for_production"

# Jinja filter for Markdown → HTML
@app.template_filter("markdown")
def markdown_filter(text):
    return Markup(markdown2.markdown(text or ""))

# ---------- Helpers ----------
def generate_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

@app.context_processor
def inject_chats():
    return {"chats": session.get("chats", [])}

@app.before_request
def require_login():
    if request.endpoint in ("login", "static"):
        return
    if "username" not in session:
        return redirect(url_for("login"))

# ---------- Background workers (use GLOBAL_* only) ----------
def _bg_ai_reply_for_solo(sid: str):
    """Generate AI reply for a solo chat using GLOBAL_MESSAGES; append result globally."""
    key = f"solo:{sid}"
    msgs = GLOBAL_MESSAGES.get(key, [])

    # Build history
    history = [{"role": "system", "content": "You are Judion, a helpful AI assistant."}]
    for m in msgs:
        history.append({"role": m["role"], "content": m["text"]})

    # Call model
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

    # Append globally
    msgs.append({
        "user": "AI",
        "role": "assistant",
        "text": ai_text,
        "ts": int(time.time())
    })
    GLOBAL_MESSAGES[key] = msgs


def _bg_judge_reply_for_debate(code: str):
    """Generate neutral judge reply for a debate; append result globally."""
    key = f"debate:{code}"
    msgs = GLOBAL_MESSAGES.get(key, [])

    # Build judge prompt & history
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

    # Call model
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

    # Append globally
    msgs.append({
        "user": "Judge",
        "role": "assistant",
        "text": ai_text,
        "ts": int(time.time())
    })
    GLOBAL_MESSAGES[key] = msgs

# ---------- Routes ----------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        if username:
            session["username"] = username
            session.setdefault("chats", [])
            return redirect(url_for("main"))
    return render_template("login.html")

@app.route("/main")
def main():
    return render_template("main.html")

# ----- Create Debate (now also registers globally) -----
@app.route("/create/debate", methods=["POST"])
def create_debate():
    title = (request.form.get("title") or "Untitled Debate").strip()
    description = (request.form.get("description") or "").strip()
    code = (request.form.get("code") or generate_code()).strip().upper()

    chat = {
        "type": "debate",
        "title": title,
        "description": description,
        "code": code
    }

    # Register globally (so *other users* can join by code)
    GLOBAL_DEBATES[code] = chat
    GLOBAL_MESSAGES.setdefault(f"debate:{code}", [])

    # Also add to THIS user's sidebar (newest first)
    session.setdefault("chats", [])
    # Prevent duplicates of the same code in this user's list
    session["chats"] = [c for c in session["chats"]
                        if not (c.get("type") == "debate" and c.get("code") == code)]
    session["chats"].insert(0, chat)
    session.modified = True

    # Go straight to the room
    return redirect(url_for("debate_room", code=code))

# ----- Join Debate by code (cross-user) -----
@app.route("/join/debate", methods=["POST"])
def join_debate():
    code = (request.form.get("code") or "").strip().upper()
    room = GLOBAL_DEBATES.get(code)
    if not room:
        return redirect(url_for("main"))

    # Add to THIS user's sidebar if not present
    session.setdefault("chats", [])
    if not any(c.get("type") == "debate" and c.get("code") == code for c in session["chats"]):
        session["chats"].insert(0, room)
        session.modified = True

    return redirect(url_for("debate_room", code=code))

# ----- Debate Room -----
@app.route("/room/<code>")
def debate_room(code):
    room = GLOBAL_DEBATES.get(code)
    if not room:
        abort(404)

    key = f"debate:{code}"
    GLOBAL_MESSAGES.setdefault(key, [])

    return render_template("debate_room.html",
                           room=room,
                           messages=GLOBAL_MESSAGES[key])

@app.post("/room/<code>/message")
def debate_message(code):
    if code not in GLOBAL_DEBATES:
        abort(404)

    text = (request.form.get("text") or "").strip()
    if text:
        key = f"debate:{code}"
        GLOBAL_MESSAGES.setdefault(key, [])

        # 1) Append user's message immediately (so it renders on reload)
        new_msg = {
            "user": session.get("username"),
            "role": "user",
            "text": text,
            "ts": int(time.time())
        }
        GLOBAL_MESSAGES[key].append(new_msg)

        # 2) Fire background judge reply
        Thread(target=_bg_judge_reply_for_debate, args=(code,), daemon=True).start()

    # 3) Redirect right away — user sees their message instantly
    return redirect(url_for("debate_room", code=code))

# ----- Create / Solo Room -----
@app.route("/create/solo", methods=["POST"])
def create_solo():
    sid = generate_code()
    chat = {"type": "solo", "sid": sid, "title": "Solo Chat", "description": ""}
    session.setdefault("chats", [])
    session["chats"].insert(0, chat)
    session.modified = True

    GLOBAL_MESSAGES.setdefault(f"solo:{sid}", [])
    return redirect(url_for("solo_room", sid=sid))

@app.route("/solo/<sid>")
def solo_room(sid):
    chats = session.get("chats", [])
    room = next((c for c in chats if c.get("type") == "solo" and c.get("sid") == sid), None)
    if not room:
        abort(404)

    key = f"solo:{sid}"
    GLOBAL_MESSAGES.setdefault(key, [])

    return render_template("solo_room.html",
                           room=room,
                           messages=GLOBAL_MESSAGES[key])

@app.post("/solo/<sid>/message")
def solo_message(sid):
    text = (request.form.get("text") or "").strip()
    if text:
        key = f"solo:{sid}"
        GLOBAL_MESSAGES.setdefault(key, [])

        # 1) Append user's message globally (render instantly)
        new_msg = {
            "user": session.get("username"),
            "role": "user",
            "text": text,
            "ts": int(time.time())
        }
        GLOBAL_MESSAGES[key].append(new_msg)

        # 2) Background AI reply
        Thread(target=_bg_ai_reply_for_solo, args=(sid,), daemon=True).start()

    return redirect(url_for("solo_room", sid=sid))

# ----- Delete chat -----
@app.post("/delete/<chat_id>")
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

        # Also clear global buffers for debates, and solo messages in this process
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
    app.run(debug=True)