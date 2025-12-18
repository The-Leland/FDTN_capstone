


import sqlite3
import bcrypt
import datetime
import csv

connection = sqlite3.connect("capstone.db")
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone TEXT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    date_created TEXT NOT NULL,
    hire_date TEXT,
    user_type TEXT NOT NULL CHECK(user_type IN ('user','manager'))
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS competencies (
    competency_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    date_created TEXT NOT NULL
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    competency_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    date_created TEXT NOT NULL,
    FOREIGN KEY (competency_id) REFERENCES competencies(competency_id),
    UNIQUE (competency_id, name)
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS assessment_results (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    assessment_id INTEGER NOT NULL,
    score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 4),
    date_taken TEXT NOT NULL,
    manager_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    FOREIGN KEY (manager_id) REFERENCES users(user_id) ON DELETE SET NULL
);
""")

connection.commit()

# def seed_manager():
#     email = "manager@example.com"
#     password = "Manager123!"
#     hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
#     cursor.execute("""
#         INSERT OR IGNORE INTO users (first_name, last_name, email, password_hash, active, user_type, date_created)
#         VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
#     """, ("Test", "Manager", email, hashed, 1, "manager"))
#     connection.commit()

# seed_manager()

def login(email, password):
    cursor.execute("SELECT user_id, password_hash, active, user_type FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()

    if row is None:
        print("Login failed: user not found.")
        return None
    
    user_id, stored_hash, active, user_type = row

    if active == 0:
        print("Login failed: user is inactive.")
        return None
    
    if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
        print(f"Login successful! Welcome {email}.")
        return {"user_id": user_id, "role": user_type}
    else:
        print("Login failed: incorrect password.")
        return None

def logout(user_info):
    if user_info:
        print(f"User {user_info['user_id']} logged out.")
    else:
        print("No active session.")

def view_profile(user_id):
    cursor.execute("""
        SELECT first_name, last_name, phone, email, hire_date, user_type, active, date_created
        FROM users
        WHERE user_id = ?
    """, (user_id,))
    row = cursor.fetchone()
    if row:
        print("\n--- Your Profile ---")
        print(f"Name: {row[0]} {row[1]}")
        print(f"Phone: {row[2]}")
        print(f"Email: {row[3]}")
        print(f"Hire Date: {row[4]}")
        print(f"User Type: {row[5]}")
        print(f"Active: {row[6]}")
        print(f"Date Created: {row[7]}")
    else:
        print("Profile not found.")

def edit_profile(user_id):
    print("\n--- Edit Profile ---")
    choice = input("What would you like to edit? (name/phone/password): ").strip().lower()

    if choice == "name":
        first = input("New first name: ")
        last = input("New last name: ")
        cursor.execute("UPDATE users SET first_name = ?, last_name = ? WHERE user_id = ?", (first, last, user_id))
        connection.commit()
        print("Name updated successfully.")

    elif choice == "phone":
        phone = input("New phone number: ")
        cursor.execute("UPDATE users SET phone = ? WHERE user_id = ?", (phone, user_id))
        connection.commit()
        print("Phone updated successfully.")

    elif choice == "password":
        new_pw = input("New password: ")
        hashed = bcrypt.hashpw(new_pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cursor.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (hashed, user_id))
        connection.commit()
        print("Password updated successfully.")
        
    else:
        print("Invalid choice.")

# --- Reports ---
def report_user_competency_summary():
    user_id = input("Enter user ID: ").strip()
    cursor.execute("SELECT first_name, last_name, email FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        print("User not found.")
        return
    cursor.execute("SELECT competency_id, name FROM competencies ORDER BY name")
    comps = cursor.fetchall()
    rows = []
    for comp_id, comp_name in comps:
        cursor.execute("""
            SELECT r.score, r.date_taken, a.name
            FROM assessment_results r
            JOIN assessments a ON r.assessment_id = a.assessment_id
            WHERE r.user_id = ? AND a.competency_id = ?
            ORDER BY r.date_taken DESC
            LIMIT 1
        """, (user_id, comp_id))
        latest = cursor.fetchone()
        if latest:
            score, date_taken, assessment_name = latest
        else:
            score, date_taken, assessment_name = 0, "", ""
        rows.append((comp_name, assessment_name, score, date_taken))
    total = sum(r[2] for r in rows)
    count = max(len(rows), 1)
    avg = total / count
    print(f"\nUser: {user[0]} {user[1]} | Email: {user[2]}")
    print("Competency | Assessment | Score | Date Taken")
    for comp_name, assessment_name, score, date_taken in rows:
        print(f"{comp_name} | {assessment_name} | {score} | {date_taken}")
    print(f"Average competency score: {avg:.2f}")

def report_competency_results_summary():
    competency_id = input("Enter competency ID: ").strip()
    cursor.execute("SELECT name FROM competencies WHERE competency_id = ?", (competency_id,))
    c = cursor.fetchone()
    if not c:
        print("Competency not found.")
        return
    competency_name = c[0]
    cursor.execute("SELECT user_id, first_name, last_name FROM users WHERE active = 1 ORDER BY last_name, first_name")
    users = cursor.fetchall()
    rows = []
    for uid, first, last in users:
        cursor.execute("""
            SELECT r.score, r.date_taken, a.name
            FROM assessment_results r
            JOIN assessments a ON r.assessment_id = a.assessment_id
            WHERE r.user_id = ? AND a.competency_id = ?
            ORDER BY r.date_taken DESC
            LIMIT 1
        """, (uid, competency_id))
        latest = cursor.fetchone()
        if latest:
            score, date_taken, assessment_name = latest
        else:
            score, date_taken, assessment_name = 0, "", ""
        rows.append((f"{first} {last}", score, assessment_name, date_taken))
    total = sum(r[1] for r in rows)
    count = max(len(rows), 1)
    avg = total / count
    print(f"\nCompetency: {competency_name}")
    print(f"Average score across active users: {avg:.2f}")
    print("Name | Score | Assessment | Date Taken")
    for name, score, assessment_name, date_taken in rows:
        print(f"{name} | {score} | {assessment_name} | {date_taken}")

# --- CSV Import/Export ---
def import_results_from_csv(filename):
    try:
        with open(filename, newline="") as f:
            reader = csv.DictReader(f)
            required = {"user_id", "assessment_id", "score", "date_taken"}
            if not required.issubset(set(reader.fieldnames or [])):
                print("CSV missing required headers.")
                return
            to_insert = []
            for row in reader:
                try:
                    user_id = int(row["user_id"])
                    assessment_id = int(row["assessment_id"])
                    score = int(row["score"])
                    date_taken = row["date_taken"].strip()
                    if score < 0 or score > 4 or not date_taken:
                        continue
                    to_insert.append((user_id, assessment_id, score, date_taken, None, datetime.datetime.now().isoformat()))
                except Exception:
                    continue
            if not to_insert:
                print("No valid rows to import.")
                return
            cursor.executemany("""
                INSERT INTO assessment_results (user_id