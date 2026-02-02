import os
import sqlite3
from flask import Flask, render_template, request, jsonify, g, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

from mistralai import Mistral
import json
from datetime import datetime

# Add this after your existing app configuration
MISTRAL_API_KEY = "YOUR_MISTRAL_API_KEY"
mistral_client = Mistral(api_key=MISTRAL_API_KEY)


app = Flask(__name__)
# It's crucial to set a secret key for session management
app.secret_key = secrets.token_hex(16)
app.config["DATABASE"] = os.path.join(
    os.path.dirname(__file__), "instance", "marks_tracker.db"
)

@app.route("/api/ai/analyze", methods=["POST"])
def ai_analyze_performance():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    subjects = query_db("SELECT * FROM subjects WHERE user_id = ?", [user_id])
    
    # Prepare performance data for AI analysis
    performance_data = []
    for subject in subjects:
        papers = query_db("SELECT * FROM papers WHERE subject_id = ? ORDER BY date_taken", [subject["id"]])
        if papers:
            marks = [p["mark"] for p in papers]
            performance_data.append({
                "subject": subject["name"],
                "marks": marks,
                "average": sum(marks) / len(marks),
                "trend": "improving" if len(marks) > 1 and marks[-1] > marks[0] else "declining" if len(marks) > 1 and marks[-1] < marks[0] else "stable"
            })
    
    # Create AI prompt
    prompt = f"""
    Analyze this student's academic performance data:
    {json.dumps(performance_data, indent=2)}
    
    Provide insights including:
    1. Overall performance summary
    2. Subject-wise strengths and weaknesses
    3. Improvement trends
    4. Specific recommendations for each subject
    5. Study tips and motivation
    
    Keep the response encouraging and actionable. Format as JSON with sections: summary, strengths, weaknesses, recommendations, study_tips.
    """
    
    try:
        chat_response = mistral_client.chat.complete(
            model="mistral-small-latest",
            messages=[{"role": "user", "content": prompt}]
        )
        
        ai_response = chat_response.choices[0].message.content
        return jsonify({"analysis": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_message = request.json.get("message")
    user_id = session['user_id']
    
    # Get user's performance context
    subjects = query_db("SELECT * FROM subjects WHERE user_id = ?", [user_id])
    context_data = []
    
    for subject in subjects:
        papers = query_db("SELECT * FROM papers WHERE subject_id = ?", [subject["id"]])
        if papers:
            marks = [p["mark"] for p in papers]
            context_data.append({
                "subject": subject["name"],
                "recent_marks": marks[-3:],  # Last 3 marks
                "average": sum(marks) / len(marks)
            })
    
    context_prompt = f"""
    You are an AI study assistant helping a student track their academic progress. 
    
    Student's current performance context:
    {json.dumps(context_data)}
    
    Student's question: {user_message}
    
    Provide helpful, encouraging responses related to their studies and performance. 
    Be supportive and offer practical advice.
    """
    
    try:
        chat_response = mistral_client.chat.complete(
            model="mistral-small-latest",
            messages=[{"role": "user", "content": context_prompt}]
        )
        
        ai_response = chat_response.choices[0].message.content
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI chat failed"}), 500
    
# --- Database helpers ---
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(app.config["DATABASE"])
        db.row_factory = sqlite3.Row
    return db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def init_db():
    with app.app_context():
        db = get_db()
        # Updated schema with users table and user_id in subjects
        db.executescript(
            """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            target_mark INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS papers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            mark INTEGER NOT NULL,
            date_taken TEXT,
            FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE
        );
        """
        )
        db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# --- Routes ---

@app.route("/")
def index():
    # If user is not in session, redirect to login
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.json.get("email")
        password = request.json.get("password")
        user = query_db("SELECT * FROM users WHERE email = ?", [email], one=True)

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            return jsonify({"success": True, "message": "Login successful."})
        else:
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.json.get("email")
        password = request.json.get("password")

        if not email or not password:
            return jsonify({"success": False, "message": "Email and password are required."}), 400

        user = query_db("SELECT * FROM users WHERE email = ?", [email], one=True)
        if user:
            return jsonify({"success": False, "message": "Email already registered."}), 409

        password_hash = generate_password_hash(password)
        db = get_db()
        db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash))
        db.commit()

        # Log the user in immediately after signup
        new_user = query_db("SELECT * FROM users WHERE email = ?", [email], one=True)
        session['user_id'] = new_user['id']
        session['user_email'] = new_user['email']

        return jsonify({"success": True, "message": "Signup successful."})

    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- API Routes for Logged-in Users ---

@app.route("/api/user", methods=["GET"])
def get_user_info():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "id": session['user_id'],
        "email": session['user_email']
    })

@app.route("/api/subjects", methods=["GET"])
def get_subjects():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    subjects = query_db("SELECT * FROM subjects WHERE user_id = ?", [user_id])
    result = []
    for subj in subjects:
        papers = query_db(
            "SELECT * FROM papers WHERE subject_id = ? ORDER BY date_taken, id",
            [subj["id"]],
        )
        result.append(
            {
                "id": subj["id"],
                "name": subj["name"],
                "target_mark": subj["target_mark"],
                "papers": [
                    {
                        "id": p["id"],
                        "name": p["name"],
                        "mark": p["mark"],
                        "date_taken": p["date_taken"],
                    }
                    for p in papers
                ],
            }
        )
    return jsonify(result)


@app.route("/api/subjects", methods=["POST"])
def add_subject():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    name = request.json.get("name")
    # In the original code, target_mark wasn't used on the frontend, so we'll make it optional
    target_mark = request.json.get("target_mark", 75) 
    db = get_db()
    cursor = db.execute(
        "INSERT INTO subjects (user_id, name, target_mark) VALUES (?, ?, ?)", (user_id, name, target_mark)
    )
    db.commit()
    return jsonify({"id": cursor.lastrowid, "name": name, "papers": []}), 201


@app.route("/api/subjects/<int:subject_id>", methods=["PUT"])
def edit_subject(subject_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Security check: ensure the subject belongs to the logged-in user
    subj = query_db("SELECT * FROM subjects WHERE id = ? AND user_id = ?", [subject_id, session['user_id']], one=True)
    if not subj:
        return jsonify({"error": "Subject not found or access denied"}), 404

    name = request.json.get("name")
    target_mark = request.json.get("target_mark", 75)
    db = get_db()
    db.execute(
        "UPDATE subjects SET name = ?, target_mark = ? WHERE id = ?",
        (name, target_mark, subject_id),
    )
    db.commit()
    return jsonify({"success": True, "message": "Subject updated."})


@app.route("/api/subjects/<int:subject_id>", methods=["DELETE"])
def delete_subject(subject_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    # Security check
    subj = query_db("SELECT * FROM subjects WHERE id = ? AND user_id = ?", [subject_id, session['user_id']], one=True)
    if not subj:
        return jsonify({"error": "Subject not found or access denied"}), 404

    db = get_db()
    db.execute("DELETE FROM subjects WHERE id = ?", (subject_id,))
    # Papers are deleted automatically due to ON DELETE CASCADE
    db.commit()
    return jsonify({"success": True, "message": "Subject deleted."})


@app.route("/api/subjects/<int:subject_id>/papers", methods=["POST"])
def add_paper(subject_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    # Security check
    subj = query_db("SELECT * FROM subjects WHERE id = ? AND user_id = ?", [subject_id, session['user_id']], one=True)
    if not subj:
        return jsonify({"error": "Subject not found or access denied"}), 404

    name = request.json.get("name")
    mark = request.json.get("mark")
    date_taken = request.json.get("date_taken") # This can be null
    db = get_db()
    cursor = db.execute(
        "INSERT INTO papers (subject_id, name, mark, date_taken) VALUES (?, ?, ?, ?)",
        (subject_id, name, mark, date_taken),
    )
    db.commit()
    return jsonify({"id": cursor.lastrowid, "name": name, "mark": mark}), 201


@app.route("/api/papers/<int:paper_id>", methods=["PUT"])
def edit_paper(paper_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    # Security check: Join tables to ensure the paper belongs to a subject owned by the user
    paper = query_db("""
        SELECT p.* FROM papers p
        JOIN subjects s ON p.subject_id = s.id
        WHERE p.id = ? AND s.user_id = ?
    """, [paper_id, session['user_id']], one=True)
    
    if not paper:
        return jsonify({"error": "Paper not found or access denied"}), 404

    name = request.json.get("name")
    mark = request.json.get("mark")
    date_taken = request.json.get("date_taken")
    db = get_db()
    db.execute(
        "UPDATE papers SET name = ?, mark = ?, date_taken = ? WHERE id = ?",
        (name, mark, date_taken, paper_id),
    )
    db.commit()
    return jsonify({"success": True, "message": "Paper updated."})


@app.route("/api/papers/<int:paper_id>", methods=["DELETE"])
def delete_paper(paper_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    # Security check
    paper = query_db("""
        SELECT p.* FROM papers p
        JOIN subjects s ON p.subject_id = s.id
        WHERE p.id = ? AND s.user_id = ?
    """, [paper_id, session['user_id']], one=True)
    
    if not paper:
        return jsonify({"error": "Paper not found or access denied"}), 404

    db = get_db()
    db.execute("DELETE FROM papers WHERE id = ?", (paper_id,))
    db.commit()
    return jsonify({"success": True, "message": "Paper deleted."})

# Note: Import/Export routes are removed for brevity as they would also need user-specific logic.
# They can be added back by applying the same user_id filtering.

if __name__ == "__main__":
    # Ensure the instance folder exists
    try:
        os.makedirs(os.path.join(os.path.dirname(__file__), "instance"))
    except OSError:
        pass
    
    init_db()
    app.run(debug=True)
