from flask import Flask, render_template, request, redirect, url_for, session, abort
import random, string, time
from dotenv import load_dotenv
import os
from openai import OpenAI
import markdown2
from markupsafe import Markup

# ----------------- Global Storage -----------------
GLOBAL_DEBATES = {}      # { code: {title, description, creator} }
GLOBAL_MESSAGES = {}     # { "debate:CODE": [messages...] }

# Load environment variables from .env file
load_dotenv()

# Read the OpenAI key
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY)

app = Flask(__name__)
app.secret_key = "change_me_for_production"

# ---------- Filters ----------
@app.template_filter("markdown")
def markdown_filter(text):
    return Markup(markdown2.markdown(text))

# ---------- Helpers ----------
def generate_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

@app.context_processor
def inject_chats():
    # Only show personal solo chats in sidebar for now
    return {"chats": session.get("chats", [])}

@app.before_request
def require_login():
    if request.endpoint in ("login", "static"):
        return
    if "username" not in session:
        return redirect(url_for("login"))

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

# ----- Create Debate -----
@app.route("/create/debate", methods=["POST"])
def create_debate():
    title = (request.form.get("title") or "Untitled Debate").strip()
    description = (request.form.get("description") or "").strip()
    code = (request.form.get("code") or generate_code()).upper()

    GLOBAL_DEBATES[code] = {
        "title": title,
        "description": description,
        "creator": session["username"]
    }
    GLOBAL_MESSAGES.setdefault(f"debate:{code}", [])

    return redirect(url_for("main"))

# ----- Join Debate -----
@app.route("/join/debate", methods=["POST"])
def join_debate():
    code = (request.form.get("code") or "").strip().upper()
    if code in GLOBAL_DEBATES:
        return redirect(url_for("debate_room", code=code))
    return redirect(url_for("main"))

# ----- Debate Room -----
@app.route("/room/<code>")
def debate_room(code):
    room = GLOBAL_DEBATES.get(code)
    if not room:
        abort(404)
    messages = GLOBAL_MESSAGES.setdefault(f"debate:{code}", [])
    return render_template("debate_room.html", room={"code": code, **room}, messages=messages)

@app.post("/room/<code>/message")
def debate_message(code):
    if code not in GLOBAL_DEBATES:
        abort(404)

    text = (request.form.get("text") or "").strip()
    if text:
        key = f"debate:{code}"
        GLOBAL_MESSAGES.setdefault(key, [])

        # Save user message
        GLOBAL_MESSAGES[key].append({
            "user": session.get("username"),
            "role": "user",
            "text": text,
            "ts": int(time.time())
        })

        # --- Neutral Judge AI ---
        try:
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

            for m in GLOBAL_MESSAGES[key]:
                history.append({
                    "role": "user" if m["role"] == "user" else "assistant",
                    "content": f"{m['user']}: {m['text']}"
                })

            response = client.chat.completions.create(
                model="gpt-4o",
                messages=history,
                max_completion_tokens=400
            )
            ai_text = response.choices[0].message.content.strip()

            GLOBAL_MESSAGES[key].append({
                "user": "Judge",
                "role": "assistant",
                "text": ai_text,
                "ts": int(time.time())
            })

        except Exception as e:
            GLOBAL_MESSAGES[key].append({
                "user": "Judge",
                "role": "assistant",
                "text": f"(Error from Judge: {e})",
                "ts": int(time.time())
            })

    return redirect(url_for("debate_room", code=code))

# ----- Solo Room -----
@app.route("/create/solo", methods=["POST"])
def create_solo():
    sid = generate_code()
    chat = {
        "type": "solo",
        "sid": sid,
        "title": "Solo Chat",
        "description": ""
    }
    session.setdefault("chats", [])
    session["chats"].insert(0, chat)
    session.modified = True
    return redirect(url_for("solo_room", sid=sid))

@app.route("/solo/<sid>")
def solo_room(sid):
    chats = session.get("chats", [])
    room = next((c for c in chats if c.get("type") == "solo" and c.get("sid") == sid), None)
    if not room:
        abort(404)
    session.setdefault("messages", {})
    session["messages"].setdefault(f"solo:{sid}", [])
    session.modified = True
    return render_template("solo_room.html", room=room, messages=session["messages"][f"solo:{sid}"])

@app.post("/solo/<sid>/message")
def solo_message(sid):
    text = (request.form.get("text") or "").strip()
    if text:
        session.setdefault("messages", {})
        key = f"solo:{sid}"
        session["messages"].setdefault(key, [])

        session["messages"][key].append({
            "user": session.get("username"),
            "role": "user",
            "text": text,
            "ts": int(time.time())
        })

        try:
            history = [{"role": "system", "content": "You are Judion, a helpful AI assistant."}]
            for m in session["messages"][key]:
                history.append({
                    "role": m["role"],
                    "content": m["text"]
                })

            response = client.chat.completions.create(
                model="gpt-4o",
                messages=history,
                max_completion_tokens=300
            )
            ai_text = response.choices[0].message.content.strip()

            session["messages"][key].append({
                "user": "AI",
                "role": "assistant",
                "text": ai_text,
                "ts": int(time.time())
            })

        except Exception as e:
            session["messages"][key].append({
                "user": "AI",
                "role": "assistant",
                "text": f"(Error: {e})",
                "ts": int(time.time())
            })

        session.modified = True

    return redirect(url_for("solo_room", sid=sid))

# ----- Delete chat -----
@app.post("/delete/<chat_id>")
def delete_chat(chat_id):
    chats = session.get("chats", [])
    found_idx = None
    found_chat = None
    for i, c in enumerate(chats):
        if (c.get("type") == "debate" and c.get("code") == chat_id) or (c.get("type") == "solo" and c.get("sid") == chat_id):
            found_idx = i
            found_chat = c
            break
    if found_idx is not None:
        chats.pop(found_idx)
        session["chats"] = chats
        if found_chat.get("type") == "debate":
            key = f"debate:{found_chat.get('code')}"
            GLOBAL_DEBATES.pop(found_chat.get("code"), None)
            GLOBAL_MESSAGES.pop(key, None)
        else:
            key = f"solo:{found_chat.get('sid')}"
            if "messages" in session and key in session["messages"]:
                session["messages"].pop(key, None)
        session.modified = True
    return redirect(url_for("main"))

if __name__ == "__main__":
    app.run(debug=True, port=5001)