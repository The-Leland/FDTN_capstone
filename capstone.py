


import sqlite3


connection = sqlite3.connect('competency_database.db')

cursor = connection.cursor()

import uuid

import csv

import datetime

import bcrypt






connection = sqlite3.connect("competency_database.sqlite")
cursor = connection.cursor()

cursor.execute("PRAGMA foreign_keys = ON;")


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
    manager_id INTEGER,can 
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    FOREIGN KEY (manager_id) REFERENCES users(user_id) ON DELETE SET NULL
);
""")

connection.commit()
# connection.close()


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


if __name__ == "__main__":
    
    email = input("Email: ")
    password = input("Password: ")

    user_info = login(email, password)

    if user_info:
        print(f"Role: {user_info['role']}")
        
        logout(user_info)



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
    while True:
        print("\n--- Edit Profile ---")
        print("1. Change Name")
        print("2. Change Phone")
        print("3. Change Password")
        print("4. Back to User Menu")

        choice = input("Select an option: ").strip()

        if choice == "1":
            first = input("New first name: ").strip()
            last = input("New last name: ").strip()
            if first and last:
                cursor.execute("UPDATE users SET first_name = ?, last_name = ? WHERE user_id = ?", (first, last, user_id))
                connection.commit()
                print("Name updated successfully.")
            else:
                print("Name update cancelled (empty values).")

        elif choice == "2":
            phone = input("New phone number: ").strip()
            if phone:
                cursor.execute("UPDATE users SET phone = ? WHERE user_id = ?", (phone, user_id))
                connection.commit()
                print("Phone updated successfully.")
            else:
                print("Phone update cancelled (empty value).")

        elif choice == "3":
            new_pw = input("New password: ").strip()
            confirm_pw = input("Confirm new password: ").strip()
            if new_pw and new_pw == confirm_pw:
                hashed = bcrypt.hashpw(new_pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                cursor.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (hashed, user_id))
                connection.commit()
                print("Password updated successfully.")
            else:
                print("Password update cancelled (empty or mismatch).")

        elif choice == "4":
            break

        else:
            print("Invalid choice.")



def create_user():
    print("\n--- Create User ---")
    first = input("First name: ").strip()
    last = input("Last name: ").strip()
    phone = input("Phone: ").strip()
    email = input("Email: ").strip()
    password = input("Password: ").strip()
    user_type = input("User type (user/manager): ").strip().lower()
    hire_date = input("Hire date (YYYY-MM-DD): ").strip()

    if user_type not in ("user", "manager"):
        print("Invalid user type.")
        return

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        cursor.execute("""
            INSERT INTO users (first_name, last_name, phone, email, password_hash, active, date_created, hire_date, user_type)
            VALUES (?, ?, ?, ?, ?, 1, datetime('now'), ?, ?)
        """, (first, last, phone, email, hashed, hire_date, user_type))
        connection.commit()
        print("User created successfully.")
    except sqlite3.IntegrityError:
        print("Error: Email must be unique.")

def view_users():
    print("\n--- All Users ---")
    cursor.execute("""
        SELECT user_id, first_name, last_name, email, phone, hire_date, user_type, active, date_created
        FROM users
        ORDER BY last_name, first_name
    """)
    rows = cursor.fetchall()
    if not rows:
        print("No users found.")
        return
    for r in rows:
        print(f"ID: {r[0]} | {r[1]} {r[2]} | {r[3]} | Phone: {r[4]} | Hire: {r[5]} | Type: {r[6]} | Active: {r[7]} | Created: {r[8]}")

def update_user():
    print("\n--- Update User ---")
    uid = input("Enter user ID to update: ").strip()
    cursor.execute("SELECT user_id, first_name, last_name, email FROM users WHERE user_id = ?", (uid,))
    user = cursor.fetchone()
    if not user:
        print("User not found.")
        return

    print(f"Updating {user[1]} {user[2]} ({user[3]})")
    field = input("Which field to update? (first_name, last_name, phone, email, password, hire_date, active, user_type): ").strip().lower()
    new_value = input("Enter new value: ").strip()

    if field == "password":
        new_value = bcrypt.hashpw(new_value.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        field = "password_hash"

    try:
        cursor.execute(f"UPDATE users SET {field} = ? WHERE user_id = ?", (new_value, uid))
        connection.commit()
        print("User updated successfully.")
    except sqlite3.Error as e:
        print(f"Error updating user: {e}")

def delete_user():
    print("\n--- Delete User ---")
    uid = input("Enter user ID to delete: ").strip()
    cursor.execute("SELECT first_name, last_name FROM users WHERE user_id = ?", (uid,))
    user = cursor.fetchone()
    if not user:
        print("User not found.")
        return
    confirm = input(f"Are you sure you want to delete {user[0]} {user[1]}? (y/n): ").strip().lower()
    if confirm == "y":
        try:
            cursor.execute("DELETE FROM users WHERE user_id = ?", (uid,))
            connection.commit()
            print("User deleted successfully.")
        except sqlite3.Error as e:
            print(f"Error deleting user: {e}")
    else:
        print("Delete cancelled.")


def search_users_by_name():
    print("\n--- Search Users by Name ---")
    name = input("Enter first or last name to search: ").strip()
    if not name:
        print("Search cancelled (empty value).")
        return

    cursor.execute("""
        SELECT user_id, first_name, last_name, email, phone, hire_date, user_type, active
        FROM users
        WHERE first_name LIKE ? OR last_name LIKE ?
        ORDER BY last_name, first_name
    """, (f"%{name}%", f"%{name}%"))
    rows = cursor.fetchall()

    if rows:
        for r in rows:
            print(f"ID: {r[0]} | {r[1]} {r[2]} | Email: {r[3]} | Phone: {r[4]} | "
                  f"Hire Date: {r[5]} | Type: {r[6]} | Active: {r[7]}")
    else:
        print("No users found with that name.")




def search_user_by_email():
    print("\n--- Search User by Email ---")
    email = input("Enter email to search: ").strip()
    cursor.execute("""
        SELECT user_id, first_name, last_name, phone, email, hire_date, user_type, active
        FROM users
        WHERE email = ?
    """, (email,))
    user = cursor.fetchone()
    if user:
        print(f"ID: {user[0]} | {user[1]} {user[2]} | Phone: {user[3]} | Email: {user[4]} | Hire Date: {user[5]} | Type: {user[6]} | Active: {user[7]}")
    else:
        print("No user found with that email.")



def report_user_competency_summary(user_id):
    print("\n--- User Competency Summary ---")

    cursor.execute("SELECT first_name, last_name, email FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        print("User not found.")
        return

    print(f"User: {user[0]} {user[1]} | Email: {user[2]}")

    cursor.execute("SELECT competency_id, name FROM competencies ORDER BY name")
    competencies = cursor.fetchall()
    if not competencies:
        print("No competencies found.")
        return

    total_score = 0
    count = 0

    for comp_id, comp_name in competencies:
        cursor.execute("""
            SELECT r.score, r.date_taken, a.name
            FROM assessment_results r
            JOIN assessments a ON r.assessment_id = a.assessment_id
            WHERE r.user_id = ? AND a.competency_id = ?
            ORDER BY r.date_taken DESC
            LIMIT 1
        """, (user_id, comp_id))
        result = cursor.fetchone()

        if result:
            score, date_taken, assessment_name = result
        else:
            score, date_taken, assessment_name = 0, None, None

        print(f"Competency: {comp_name} | Score: {score} | Assessment: {assessment_name or ''} | Date: {date_taken or ''}")

        total_score += score
        count += 1

    avg_score = total_score / count if count > 0 else 0
    print(f"\nAverage Competency Score: {avg_score:.2f}")



def report_competency_results_summary(competency_id):
    print("\n--- Competency Results Summary ---")

    # Get competency info
    cursor.execute("SELECT name FROM competencies WHERE competency_id = ?", (competency_id,))
    comp = cursor.fetchone()
    if not comp:
        print("Competency not found.")
        return

    comp_name = comp[0]
    print(f"Competency: {comp_name}")

    # Get all active users
    cursor.execute("SELECT user_id, first_name, last_name FROM users WHERE active = 1 ORDER BY last_name, first_name")
    users = cursor.fetchall()
    if not users:
        print("No active users found.")
        return

    total_score = 0
    count = 0

    for user_id, first_name, last_name in users:
        # Get most recent result for this competency for the user
        cursor.execute("""
            SELECT r.score, r.date_taken, a.name
            FROM assessment_results r
            JOIN assessments a ON r.assessment_id = a.assessment_id
            WHERE r.user_id = ? AND a.competency_id = ?
            ORDER BY r.date_taken DESC
            LIMIT 1
        """, (user_id, competency_id))
        result = cursor.fetchone()

        if result:
            score, date_taken, assessment_name = result
        else:
            score, date_taken, assessment_name = 0, None, None

        print(f"User: {first_name} {last_name} | Score: {score} | Assessment: {assessment_name or ''} | Date: {date_taken or ''}")

        total_score += score
        count += 1

    avg_score = total_score / count if count > 0 else 0
    print(f"\nAverage Score for {comp_name}: {avg_score:.2f}")


def view_assessments_for_user(user_id):
    print("\n--- My Assessment Results ---")

    cursor.execute("""
        SELECT a.name, a.competency_id, r.score, r.date_taken
        FROM assessment_results r
        JOIN assessments a ON r.assessment_id = a.assessment_id
        WHERE r.user_id = ?
        ORDER BY r.date_taken DESC
    """, (user_id,))
    results = cursor.fetchall()

    if not results:
        print("No assessment results found.")
        return

    for assessment_name, competency_id, score, date_taken in results:
        # Get competency name for clarity
        cursor.execute("SELECT name FROM competencies WHERE competency_id = ?", (competency_id,))
        comp = cursor.fetchone()
        comp_name = comp[0] if comp else "Unknown Competency"

        print(f"Assessment: {assessment_name} | Competency: {comp_name} | Score: {score} | Date: {date_taken}")



 # --- CSV Import/Export ---
def import_results_from_csv(filename):
    print(f"\n--- Import Results from {filename} ---")
    try:
        with open(filename, newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                cursor.execute("""
                    INSERT INTO assessment_results (user_id, assessment_id, score, date_taken, manager_id, created_at)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                """, (
                    row["user_id"],
                    row["assessment_id"],
                    row["score"],
                    row["date_taken"],
                    row.get("manager_id")
                ))
            connection.commit()
        print("Results imported successfully.")
    except Exception as e:
        print(f"Error importing results: {e}")

def export_users_to_csv(filename):
    print(f"\n--- Export Users to {filename} ---")
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    headers = [desc[0] for desc in cursor.description]
    try:
        with open(filename, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(rows)
        print("Users exported successfully.")
    except Exception as e:
        print(f"Error exporting users: {e}")

def export_competencies_to_csv(filename):
    print(f"\n--- Export Competencies to {filename} ---")
    cursor.execute("SELECT * FROM competencies")
    rows = cursor.fetchall()
    headers = [desc[0] for desc in cursor.description]
    try:
        with open(filename, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(rows)
        print("Competencies exported successfully.")
    except Exception as e:
        print(f"Error exporting competencies: {e}")      



def create_competency():
    print("\n--- Create Competency ---")
    name = input("Competency name: ").strip()
    if not name:
        print("Competency name cannot be empty.")
        return
    try:
        cursor.execute("""
            INSERT INTO competencies (name, date_created)
            VALUES (?, datetime('now'))
        """, (name,))
        connection.commit()
        print("Competency created successfully.")
    except sqlite3.IntegrityError:
        print("Error: Competency name must be unique.")

def view_competencies():
    print("\n--- All Competencies ---")
    cursor.execute("SELECT competency_id, name, date_created FROM competencies ORDER BY name")
    rows = cursor.fetchall()
    if not rows:
        print("No competencies found.")
        return
    for r in rows:
        print(f"ID: {r[0]} | Name: {r[1]} | Created: {r[2]}")

def update_competency():
    print("\n--- Update Competency ---")
    cid = input("Enter competency ID to update: ").strip()
    cursor.execute("SELECT competency_id, name FROM competencies WHERE competency_id = ?", (cid,))
    comp = cursor.fetchone()
    if not comp:
        print("Competency not found.")
        return
    print(f"Updating competency: {comp[1]}")
    new_name = input("Enter new name: ").strip()
    if not new_name:
        print("Name cannot be empty.")
        return
    try:
        cursor.execute("UPDATE competencies SET name = ? WHERE competency_id = ?", (new_name, cid))
        connection.commit()
        print("Competency updated successfully.")
    except sqlite3.IntegrityError:
        print("Error: Competency name must be unique.")

def delete_competency():
    print("\n--- Delete Competency ---")
    cid = input("Enter competency ID to delete: ").strip()
    cursor.execute("SELECT name FROM competencies WHERE competency_id = ?", (cid,))
    comp = cursor.fetchone()
    if not comp:
        print("Competency not found.")
        return
    confirm = input(f"Are you sure you want to delete competency '{comp[0]}'? (y/n): ").strip().lower()
    if confirm == "y":
        try:
            cursor.execute("DELETE FROM competencies WHERE competency_id = ?", (cid,))
            connection.commit()
            print("Competency deleted successfully.")
        except sqlite3.Error as e:
            print(f"Error deleting competency: {e}")
    else:
        print("Delete cancelled.")



def create_assessment():
    print("\n--- Create Assessment ---")
    competency_id = input("Enter competency ID: ").strip()
    cursor.execute("SELECT name FROM competencies WHERE competency_id = ?", (competency_id,))
    comp = cursor.fetchone()
    if not comp:
        print("Competency not found.")
        return
    name = input("Assessment name: ").strip()
    if not name:
        print("Assessment name cannot be empty.")
        return
    try:
        cursor.execute("""
            INSERT INTO assessments (competency_id, name, date_created)
            VALUES (?, ?, datetime('now'))
        """, (competency_id, name))
        connection.commit()
        print(f"Assessment '{name}' created successfully for competency '{comp[0]}'.")
    except sqlite3.IntegrityError:
        print("Error: Assessment name must be unique within this competency.")

def view_assessments():
    print("\n--- All Assessments ---")
    cursor.execute("""
        SELECT a.assessment_id, a.name, c.name, a.date_created
        FROM assessments a
        JOIN competencies c ON a.competency_id = c.competency_id
        ORDER BY c.name, a.name
    """)
    rows = cursor.fetchall()
    if not rows:
        print("No assessments found.")
        return
    for r in rows:
        print(f"ID: {r[0]} | Assessment: {r[1]} | Competency: {r[2]} | Created: {r[3]}")

def update_assessment():
    print("\n--- Update Assessment ---")
    aid = input("Enter assessment ID to update: ").strip()
    cursor.execute("SELECT assessment_id, name FROM assessments WHERE assessment_id = ?", (aid,))
    assessment = cursor.fetchone()
    if not assessment:
        print("Assessment not found.")
        return
    print(f"Updating assessment: {assessment[1]}")
    new_name = input("Enter new name: ").strip()
    if not new_name:
        print("Name cannot be empty.")
        return
    try:
        cursor.execute("UPDATE assessments SET name = ? WHERE assessment_id = ?", (new_name, aid))
        connection.commit()
        print("Assessment updated successfully.")
    except sqlite3.IntegrityError:
        print("Error: Assessment name must be unique within its competency.")

def delete_assessment():
    print("\n--- Delete Assessment ---")
    aid = input("Enter assessment ID to delete: ").strip()
    cursor.execute("SELECT name FROM assessments WHERE assessment_id = ?", (aid,))
    assessment = cursor.fetchone()
    if not assessment:
        print("Assessment not found.")
        return
    confirm = input(f"Are you sure you want to delete assessment '{assessment[0]}'? (y/n): ").strip().lower()
    if confirm == "y":
        try:
            cursor.execute("DELETE FROM assessments WHERE assessment_id = ?", (aid,))
            connection.commit()
            print("Assessment deleted successfully.")
        except sqlite3.Error as e:
            print(f"Error deleting assessment: {e}")
    else:
        print("Delete cancelled.")



def create_result():
    print("\n--- Create Assessment Result ---")
    user_id = input("Enter user ID: ").strip()
    assessment_id = input("Enter assessment ID: ").strip()
    score = input("Enter score (0-4): ").strip()
    date_taken = input("Enter date taken (YYYY-MM-DD): ").strip()
    manager_id = input("Enter manager ID (optional, press Enter to skip): ").strip()

    try:
        score = int(score)
        if score < 0 or score > 4:
            print("Score must be between 0 and 4.")
            return
    except ValueError:
        print("Invalid score.")
        return

    manager_val = manager_id if manager_id else None

    try:
        cursor.execute("""
            INSERT INTO assessment_results (user_id, assessment_id, score, date_taken, manager_id, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        """, (user_id, assessment_id, score, date_taken, manager_val))
        connection.commit()
        print("Assessment result recorded successfully.")
    except sqlite3.Error as e:
        print(f"Error creating result: {e}")

def view_results():
    print("\n--- All Assessment Results ---")
    cursor.execute("""
        SELECT r.result_id, u.first_name || ' ' || u.last_name, a.name, r.score, r.date_taken, r.manager_id
        FROM assessment_results r
        JOIN users u ON r.user_id = u.user_id
        JOIN assessments a ON r.assessment_id = a.assessment_id
        ORDER BY r.date_taken DESC
    """)
    rows = cursor.fetchall()
    if not rows:
        print("No results found.")
        return
    for r in rows:
        print(f"ID: {r[0]} | User: {r[1]} | Assessment: {r[2]} | Score: {r[3]} | Date: {r[4]} | Manager ID: {r[5]}")

def update_result():
    print("\n--- Update Assessment Result ---")
    rid = input("Enter result ID to update: ").strip()
    cursor.execute("SELECT result_id, score, date_taken FROM assessment_results WHERE result_id = ?", (rid,))
    result = cursor.fetchone()
    if not result:
        print("Result not found.")
        return
    print(f"Updating result ID {result[0]} | Current Score: {result[1]} | Date Taken: {result[2]}")
    field = input("Which field to update? (score/date_taken/manager_id): ").strip().lower()
    new_value = input("Enter new value: ").strip()

    if field == "score":
        try:
            new_value = int(new_value)
            if new_value < 0 or new_value > 4:
                print("Score must be between 0 and 4.")
                return
        except ValueError:
            print("Invalid score.")
            return

    try:
        cursor.execute(f"UPDATE assessment_results SET {field} = ? WHERE result_id = ?", (new_value, rid))
        connection.commit()
        print("Result updated successfully.")
    except sqlite3.Error as e:
        print(f"Error updating result: {e}")

def delete_result():
    print("\n--- Delete Assessment Result ---")
    rid = input("Enter result ID to delete: ").strip()
    cursor.execute("SELECT result_id FROM assessment_results WHERE result_id = ?", (rid,))
    result = cursor.fetchone()
    if not result:
        print("Result not found.")
        return
    confirm = input(f"Are you sure you want to delete result ID {rid}? (y/n): ").strip().lower()
    if confirm == "y":
        try:
            cursor.execute("DELETE FROM assessment_results WHERE result_id = ?", (rid,))
            connection.commit()
            print("Result deleted successfully.")
        except sqlite3.Error as e:
            print(f"Error deleting result: {e}")
    else:
        print("Delete cancelled.")


def manager_menu():
    while True:
        print("\n--- Manager Menu ---")
        print("1. Manage Users")
        print("2. Manage Competencies")
        print("3. Manage Assessments")
        print("4. Manage Results")
        print("5. Search & Reporting")
        print("6. Reports & CSV")
        print("7. Logout")

        choice = input("Select an option: ").strip()

        # --- USERS ---
        if choice == "1":
            while True:
                print("\n--- Manage Users ---")
                print("1. Create User")
                print("2. View Users")
                print("3. Update User")
                print("4. Delete User")
                print("5. Back to Manager Menu")
                sub_choice = input("Select an option: ").strip()

                if sub_choice == "1":
                    create_user()
                elif sub_choice == "2":
                    view_users()
                elif sub_choice == "3":
                    update_user()
                elif sub_choice == "4":
                    delete_user()
                elif sub_choice == "5":
                    break
                else:
                    print("Invalid choice.")

        # --- COMPETENCIES ---
        elif choice == "2":
            while True:
                print("\n--- Manage Competencies ---")
                print("1. Create Competency")
                print("2. View Competencies")
                print("3. Update Competency")
                print("4. Delete Competency")
                print("5. Back to Manager Menu")
                sub_choice = input("Select an option: ").strip()

                if sub_choice == "1":
                    create_competency()
                elif sub_choice == "2":
                    view_competencies()
                elif sub_choice == "3":
                    update_competency()
                elif sub_choice == "4":
                    delete_competency()
                elif sub_choice == "5":
                    break
                else:
                    print("Invalid choice.")

        # --- ASSESSMENTS ---
        elif choice == "3":
            while True:
                print("\n--- Manage Assessments ---")
                print("1. Create Assessment")
                print("2. View Assessments")
                print("3. Update Assessment")
                print("4. Delete Assessment")
                print("5. Back to Manager Menu")
                sub_choice = input("Select an option: ").strip()

                if sub_choice == "1":
                    create_assessment()
                elif sub_choice == "2":
                    view_assessments()
                elif sub_choice == "3":
                    update_assessment()
                elif sub_choice == "4":
                    delete_assessment()
                elif sub_choice == "5":
                    break
                else:
                    print("Invalid choice.")

        # --- RESULTS ---
        elif choice == "4":
            while True:
                print("\n--- Manage Results ---")
                print("1. Create Result")
                print("2. View Results")
                print("3. Update Result")
                print("4. Delete Result")
                print("5. Back to Manager Menu")
                sub_choice = input("Select an option: ").strip()

                if sub_choice == "1":
                    create_result()
                elif sub_choice == "2":
                    view_results()
                elif sub_choice == "3":
                    update_result()
                elif sub_choice == "4":
                    delete_result()
                elif sub_choice == "5":
                    break
                else:
                    print("Invalid choice.")

        # --- SEARCH & REPORTING ---
        elif choice == "5":
            while True:
                print("\n--- Search & Reporting ---")
                print("1. Search User by Email")
                print("2. Search Users by Name")
                print("3. View Assessments for a User")
                print("4. Back to Manager Menu")
                sub_choice = input("Select an option: ").strip()

                if sub_choice == "1":
                    search_user_by_email()
                elif sub_choice == "2":
                    search_users_by_name()
                elif sub_choice == "3":
                    view_assessments_for_user()
                elif sub_choice == "4":
                    break
                else:
                    print("Invalid choice.")


        # --- REPORTS & CSV ---
        elif choice == "6":
            while True:
                print("\n--- Reports & CSV ---")
                print("1. User Competency Summary")
                print("2. Competency Results Summary")
                print("3. Import Results from CSV")
                print("4. Export Users to CSV")
                print("5. Export Competencies to CSV")
                print("6. Back to Manager Menu")
                sub_choice = input("Select an option: ").strip()

                if sub_choice == "1":
                    uid = input("Enter user ID: ").strip()
                    if uid:
                        report_user_competency_summary(uid)

                elif sub_choice == "2":
                    cid = input("Enter competency ID: ").strip()
                    if cid:
                        report_competency_results_summary(cid)   # <-- your new function wired in here

                elif sub_choice == "3":
                    filename = input("CSV filename to import: ").strip()
                    import_results_from_csv(filename)

                elif sub_choice == "4":
                    filename = input("CSV filename to export: ").strip()
                    export_users_to_csv(filename)

                elif sub_choice == "5":
                    filename = input("CSV filename to export: ").strip()
                    export_competencies_to_csv(filename)

                elif sub_choice == "6":
                    break
                else:
                    print("Invalid choice.")

        # --- LOGOUT ---
        elif choice == "7":
            logout({"role": "manager"})
            break

        else:
            print("Invalid choice.")





def user_menu(user_id):
    while True:
        print("\n--- User Menu ---")
        print("1. View Profile")
        print("2. Edit Profile")
        print("3. View Competency List")
        print("4. View Assessment List")
        print("5. View My Competency Results")
        print("6. View My Assessment Results")
        print("7. Logout")

        choice = input("Select an option: ").strip()

        if choice == "1":
            view_profile(user_id)

        elif choice == "2":
            edit_profile(user_id)

        elif choice == "3":
            view_competencies()

        elif choice == "4":
            view_assessments()

        elif choice == "5":
            report_user_competency_summary(user_id)   # <-- simplified

        elif choice == "6":
            view_assessments_for_user(user_id)        # <-- helper to implement

        elif choice == "7":
            logout({"role": "user", "user_id": user_id})
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    print("\n--- Welcome to the Competency Tracking Tool ---")
    role_choice = input("Are you logging in as a manager or user? ").strip().lower()

    if role_choice not in ("manager", "user"):
        print("Invalid role. Please restart and choose 'manager' or 'user'.")
    else:
        email = input("Email: ").strip()
        password = input("Password: ").strip()

        user_info = login(email, password)

        if user_info:
            # Double-check role matches database
            if user_info["role"] != role_choice:
                print(f"Role mismatch: you selected '{role_choice}' but your account is '{user_info['role']}'.")
            else:
                print(f"Login successful as {role_choice}.")
                if role_choice == "manager":
                    manager_menu()
                else:
                    user_menu(user_info["user_id"])

        logout(user_info)