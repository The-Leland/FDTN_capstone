


import sqlite3


connection = sqlite3.connect('competency_database.db')

cursor = connection.cursor()

import uuid

import csv

import datetime

import bcrypt




import sqlite3

connection = sqlite3.connect("competency_tracking.sqlite")
cursor = connection.cursor()

cursor.execute("PRAGMA foreign_keys = ON;")

# Users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone TEXT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    date_created TEXT NOT NULL DEFAULT (datetime('now')),
    hire_date TEXT,
    user_type TEXT NOT NULL CHECK (user_type IN ('user','manager'))
);
""")

# Competencies table
cursor.execute("""
CREATE TABLE IF NOT EXISTS competencies (
    competency_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    date_created TEXT NOT NULL DEFAULT (date('now'))
);
""")

# Assessments table
cursor.execute("""
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    competency_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    date_created TEXT NOT NULL DEFAULT (date('now')),
    FOREIGN KEY (competency_id) REFERENCES competencies(competency_id) ON DELETE CASCADE,
    UNIQUE (competency_id, name)
);
""")

# Assessment Results table
cursor.execute("""
CREATE TABLE IF NOT EXISTS assessment_results (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    assessment_id INTEGER NOT NULL,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 4),
    date_taken TEXT NOT NULL,
    manager_id INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    FOREIGN KEY (manager_id) REFERENCES users(user_id) ON DELETE SET NULL
);
""")

connection.commit()
connection.close()


import sqlite3
import bcrypt

# Connect to your database
connection = sqlite3.connect("competency_database.db")
cursor = connection.cursor()

def login(email, password):
    # Look up the user by email
    cursor.execute("SELECT user_id, password_hash, active, user_type FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()

    if row is None:
        print("Login failed: user not found.")
        return None

    user_id, stored_hash, active, user_type = row

    # Check if user is active
    if active == 0:
        print("Login failed: user is inactive.")
        return None

    # Verify password using bcrypt
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

# Example usage
if __name__ == "__main__":
    # Replace with test credentials
    email = input("Email: ")
    password = input("Password: ")

    user_info = login(email, password)

    if user_info:
        print(f"Role: {user_info['role']}")
        # Do role-based actions here
        logout(user_info)

connection.close()



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



if user_info:
    if user_info["role"] == "user":
        while True:
            print("\n--- User Menu ---")
            print("1. View Profile")
            print("2. Edit Profile")
            print("3. Logout")
            choice = input("Select an option: ")

            if choice == "1":
                view_profile(user_info["user_id"])
            elif choice == "2":
                edit_profile(user_info["user_id"])
            elif choice == "3":
                logout(user_info)
                break
            else:
                print("Invalid choice.")



if user_info:
    if user_info["role"] == "manager":
        while True:
            print("\n--- Manager Menu ---")
            print("1. Manage Users")
            print("2. Manage Competencies")
            print("3. Manage Assessments")
            print("4. Manage Results")
            print("5. Search & Reporting")
            print("6. Logout")
            choice = input("Select an option: ")

            # --- USERS ---
            if choice == "1":
                while True:
                    print("\n--- Manage Users ---")
                    print("1. Create User")
                    print("2. View Users")
                    print("3. Update User")
                    print("4. Delete User")
                    print("5. Back to Manager Menu")
                    sub_choice = input("Select an option: ")

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
                    sub_choice = input("Select an option: ")

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
                    sub_choice = input("Select an option: ")

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
                    sub_choice = input("Select an option: ")

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
                    print("2. Report Average Scores by Competency")
                    print("3. Back to Manager Menu")
                    sub_choice = input("Select an option: ")

                    if sub_choice == "1":
                        search_user_by_email()
                    elif sub_choice == "2":
                        report_average_scores()
                    elif sub_choice == "3":
                        break
                    else:
                        print("Invalid choice.")

            # --- LOGOUT ---
            elif choice == "6":
                logout(user_info)
                break

            else:
                print("Invalid choice.")

                