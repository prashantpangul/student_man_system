
import os
import re
from functools import wraps
from io import BytesIO

import pandas as pd

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from werkzeug.security import check_password_hash

from database import get_connection


app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-development-secret-before-deployment",
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# --------------------------------------------------
# Login protection
# --------------------------------------------------

def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapped_view


# --------------------------------------------------
# Role-based access protection
# --------------------------------------------------

def role_required(required_role):
    def decorator(view_function):
        @wraps(view_function)
        def wrapped_view(*args, **kwargs):
            if "admin_id" not in session:
                return redirect(url_for("login"))

            if session.get("admin_role") != required_role:
                flash(
                    "You do not have permission to access this page.",
                    "danger",
                )
                return redirect(url_for("home"))

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator


# --------------------------------------------------
# Admin and staff login
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if "admin_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash(
                "Please enter your username and password.",
                "danger",
            )
            return render_template("login.html")

        connection = get_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, username, password_hash, role
                    FROM admins
                    WHERE username = %s
                    """,
                    (username,),
                )

                admin = cursor.fetchone()

        finally:
            connection.close()

        # Verify the submitted password against the stored hash.
        password_is_valid = False

        if admin and isinstance(admin[2], str):
            password_is_valid = check_password_hash(
                admin[2],
                password,
            )

        if password_is_valid:
            session.clear()

            session["admin_id"] = admin[0]
            session["admin_username"] = admin[1]
            session["admin_role"] = admin[3]

            flash("Login successful!", "success")
            return redirect(url_for("home"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


# --------------------------------------------------
# Logout
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# --------------------------------------------------
# Validate student form data
# --------------------------------------------------

def _student_form_values():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    course = request.form.get("course", "").strip()
    age_text = request.form.get("age", "").strip()

    # Validate name
    if len(name) < 2 or len(name) > 100:
        abort(
            400,
            description="Name must contain 2 to 100 characters.",
        )

    # Validate email
    if len(email) > 100:
        abort(
            400,
            description="Email must not exceed 100 characters.",
        )

    if email and not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email,
    ):
        abort(
            400,
            description="Please enter a valid email address.",
        )

    # Validate phone number
    if phone and not re.fullmatch(
        r"[0-9+\-\s()]{7,15}",
        phone,
    ):
        abort(
            400,
            description="Enter a valid phone number.",
        )

    # Validate course
    if len(course) > 100:
        abort(
            400,
            description="Course must not exceed 100 characters.",
        )

    # Validate age
    age = None

    if age_text:
        try:
            age = int(age_text)
        except ValueError:
            abort(
                400,
                description="Age must be a whole number.",
            )

        if age < 1 or age > 100:
            abort(
                400,
                description="Age must be between 1 and 100.",
            )

    return (
        name,
        email or None,
        phone or None,
        course or None,
        age,
    )


# --------------------------------------------------
# Dashboard
# --------------------------------------------------

@app.route("/")
@login_required
def home():
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM students")
            total_students = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT COUNT(DISTINCT course)
                FROM students
                WHERE course IS NOT NULL
                  AND course != ''
                """
            )

            total_courses = cursor.fetchone()[0]

    finally:
        connection.close()

    return render_template(
        "home.html",
        total_students=total_students,
        total_courses=total_courses,
    )


# --------------------------------------------------
# View and search students
# --------------------------------------------------

@app.route("/students")
@login_required
def students():
    search = request.args.get("search", "").strip()

    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            if search:
                keyword = f"%{search}%"

                cursor.execute(
                    """
                    SELECT *
                    FROM students
                    WHERE name LIKE %s
                       OR email LIKE %s
                       OR course LIKE %s
                    ORDER BY id ASC
                    """,
                    (
                        keyword,
                        keyword,
                        keyword,
                    ),
                )

            else:
                cursor.execute(
                    """
                    SELECT *
                    FROM students
                    ORDER BY id ASC
                    """
                )

            student_rows = cursor.fetchall()

    finally:
        connection.close()

    total_students = len(student_rows)
    start_record = 1 if total_students > 0 else 0
    end_record = total_students

    return render_template(
        "students.html",
        students=student_rows,
        search=search,
        page=1,
        total_pages=1,
        total_students=total_students,
        start_record=start_record,
        end_record=end_record,
    )


# --------------------------------------------------
# Course-wise student report
# --------------------------------------------------

@app.route("/course-report")
@login_required
def course_report():
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    course,
                    COUNT(*) AS student_count
                FROM students
                WHERE course IS NOT NULL
                  AND TRIM(course) != ''
                GROUP BY course
                ORDER BY course
                """
            )

            course_rows = cursor.fetchall()

    finally:
        connection.close()

    total_enrollment = sum(row[1] for row in course_rows)

    return render_template(
        "course_report.html",
        courses=course_rows,
        total_enrollment=total_enrollment,
    )


# --------------------------------------------------
# Add a new student
# --------------------------------------------------

@app.route("/add-student", methods=["GET", "POST"])
@login_required
def add_student():
    if request.method == "GET":
        return render_template("add_student.html")

    values = _student_form_values()
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO students
                    (name, email, phone, course, age)
                VALUES (%s, %s, %s, %s, %s)
                """,
                values,
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    flash("Student added successfully!", "success")

    return redirect(url_for("students"))


# --------------------------------------------------
# Edit an existing student
# --------------------------------------------------

@app.route("/edit-student/<int:id>", methods=["GET", "POST"])
@login_required
def edit_student(id):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            if request.method == "POST":
                values = _student_form_values()

                cursor.execute(
                    "SELECT id FROM students WHERE id = %s",
                    (id,),
                )

                if cursor.fetchone() is None:
                    abort(404)

                cursor.execute(
                    """
                    UPDATE students
                    SET name = %s,
                        email = %s,
                        phone = %s,
                        course = %s,
                        age = %s
                    WHERE id = %s
                    """,
                    (*values, id),
                )

                connection.commit()

            else:
                cursor.execute(
                    "SELECT * FROM students WHERE id = %s",
                    (id,),
                )

                student = cursor.fetchone()

                if student is None:
                    abort(404)

    except Exception:
        if request.method == "POST":
            connection.rollback()
        raise

    finally:
        connection.close()

    if request.method == "POST":
        flash("Student updated successfully!", "success")
        return redirect(url_for("students"))

    return render_template(
        "edit_student.html",
        student=student,
    )


# --------------------------------------------------
# Delete a student - ADMIN ONLY
# --------------------------------------------------

@app.route("/delete-student/<int:id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_student(id):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM students WHERE id = %s",
                (id,),
            )

            deleted_count = cursor.rowcount

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    if deleted_count:
        flash("Student deleted successfully!", "success")
    else:
        flash("Student was not found.", "warning")

    return redirect(url_for("students"))


# --------------------------------------------------
# Export student records to Excel
# --------------------------------------------------

@app.route("/export-students")
@login_required
def export_students():
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, name, email, phone, course, age
                FROM students
                ORDER BY id ASC
                """
            )

            rows = cursor.fetchall()

    finally:
        connection.close()

    columns = [
        "ID",
        "Name",
        "Email",
        "Phone",
        "Course",
        "Age",
    ]

    dataframe = pd.DataFrame(rows, columns=columns)
    output = BytesIO()

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        dataframe.to_excel(
            writer,
            index=False,
            sheet_name="Students",
        )

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="student_records.xlsx",
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
    )


# --------------------------------------------------
# Run Flask application
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
