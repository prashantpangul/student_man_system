from decimal import Decimal, InvalidOperation
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

    if len(name) < 2 or len(name) > 100:
        abort(400, description="Name must contain 2 to 100 characters.")

    if len(email) > 100:
        abort(400, description="Email must not exceed 100 characters.")

    if email and not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email,
    ):
        abort(400, description="Please enter a valid email address.")

    if phone and not re.fullmatch(
        r"[0-9+\-\s()]{7,15}",
        phone,
    ):
        abort(400, description="Enter a valid phone number.")

    if len(course) > 100:
        abort(400, description="Course must not exceed 100 characters.")

    age = None

    if age_text:
        try:
            age = int(age_text)
        except ValueError:
            abort(400, description="Age must be a whole number.")

        if age < 1 or age > 100:
            abort(400, description="Age must be between 1 and 100.")

    return name, email or None, phone or None, course or None, age


# --------------------------------------------------
# Validate fee form data
# --------------------------------------------------

def _fee_form_values():
    total_text = request.form.get("total_fee", "").strip()
    paid_text = request.form.get("paid_amount", "").strip()

    try:
        total_fee = Decimal(total_text)
        paid_amount = Decimal(paid_text)
    except (InvalidOperation, ValueError):
        return None

    if (
        not total_fee.is_finite()
        or not paid_amount.is_finite()
        or total_fee < 0
        or paid_amount < 0
        or paid_amount > total_fee
        or total_fee > Decimal("99999999.99")
        or paid_amount > Decimal("99999999.99")
        or total_fee.as_tuple().exponent < -2
        or paid_amount.as_tuple().exponent < -2
    ):
        return None

    return total_fee, paid_amount


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
# View and search students with fee status
# --------------------------------------------------

@app.route("/students")
@login_required
def students():
    search = request.args.get("search", "").strip()
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            query = """
                SELECT
                    s.id,
                    s.name,
                    s.email,
                    s.phone,
                    s.course,
                    s.age,
                    COALESCE(NULLIF(f.total_fee, 0), 50000.00) AS total_fee,
                    COALESCE(f.paid_amount, 0.00) AS paid_amount
                FROM students AS s
                LEFT JOIN student_fees AS f
                    ON s.id = f.student_id
            """

            if search:
                keyword = f"%{search}%"
                query += """
                    WHERE s.name LIKE %s
                       OR s.email LIKE %s
                       OR s.course LIKE %s
                """
                cursor.execute(
                    query + " ORDER BY s.id ASC",
                    (keyword, keyword, keyword),
                )
            else:
                cursor.execute(query + " ORDER BY s.id ASC")

            student_rows = cursor.fetchall()

    finally:
        connection.close()

    students_with_fees = []

    for student in student_rows:
        total_fee = Decimal(str(student[6]))
        paid_amount = Decimal(str(student[7]))

        if total_fee > 0 and paid_amount >= total_fee:
            status = "Paid"
        elif paid_amount > 0:
            status = "Partial"
        else:
            status = "Pending"

        students_with_fees.append(student + (status,))

    total_students = len(students_with_fees)

    return render_template(
        "students.html",
        students=students_with_fees,
        search=search,
        page=1,
        total_pages=1,
        total_students=total_students,
        start_record=1 if total_students else 0,
        end_record=total_students,
    )


# --------------------------------------------------
# Update student info and fees (one page)
# --------------------------------------------------

@app.route("/update-student/<int:id>", methods=["GET", "POST"])
@login_required
def update_student(id):
    is_admin = session.get("admin_role") == "admin"
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, name, email, phone, course, age
                FROM students
                WHERE id = %s
                """,
                (id,),
            )
            student = cursor.fetchone()

            if student is None:
                abort(404)

            if request.method == "POST":
                values = _student_form_values()
                fee_values = None

                if is_admin:
                    fee_values = _fee_form_values()

                    if fee_values is None:
                        flash(
                            "Enter valid amounts with up to two decimal "
                            "places. Paid amount cannot exceed total fee.",
                            "danger",
                        )
                        return redirect(url_for("update_student", id=id))

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

                if fee_values is not None:
                    cursor.execute(
                        """
                        INSERT INTO student_fees
                            (student_id, total_fee, paid_amount)
                        VALUES (%s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                            total_fee = VALUES(total_fee),
                            paid_amount = VALUES(paid_amount)
                        """,
                        (id, *fee_values),
                    )

                connection.commit()
                flash("Student updated successfully!", "success")
                return redirect(url_for("students"))

            cursor.execute(
                """
                SELECT total_fee, paid_amount
                FROM student_fees
                WHERE student_id = %s
                """,
                (id,),
            )
            fee_record = cursor.fetchone()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    total_fee = (
        fee_record[0]
        if fee_record and fee_record[0]
        else Decimal("50000.00")
    )
    paid_amount = fee_record[1] if fee_record else Decimal("0.00")

    return render_template(
        "update_student.html",
        student=student,
        total_fee=total_fee,
        paid_amount=paid_amount,
        is_admin=is_admin,
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
                SELECT course, COUNT(*) AS student_count
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
                INSERT INTO students (name, email, phone, course, age)
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

    columns = ["ID", "Name", "Email", "Phone", "Course", "Age"]
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