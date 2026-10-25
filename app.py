import os
import re
from decimal import Decimal, InvalidOperation
from functools import wraps
from io import BytesIO

import pandas as pd
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_file,
)
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from database import get_connection


# =========================================================
# FLASK CONFIGURATION
# =========================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-development-secret-before-deployment"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# =========================================================
# SESSION INFORMATION
# =========================================================

@app.context_processor
def inject_session_info():
    return {
        "is_logged_in": "admin_id" in session,
        "is_root": session.get("is_root", False),
        "current_username": session.get("admin_username", ""),
        "workspace_username": session.get(
            "workspace_username",
            session.get("admin_username", "")
        ),
    }


# =========================================================
# LOGIN AND ROLE DECORATORS
# =========================================================

def login_required(view_function):
    @wraps(view_function)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapper


def role_required(required_role):
    def decorator(view_function):
        @wraps(view_function)
        def wrapper(*args, **kwargs):
            if "admin_id" not in session:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))

            if session.get("admin_role") != required_role:
                flash("You do not have permission to perform this action.", "error")
                return redirect(url_for("home"))

            return view_function(*args, **kwargs)

        return wrapper

    return decorator


def root_required(view_function):
    @wraps(view_function)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        if not session.get("is_root", False):
            flash("Only the root administrator can manage user workspaces.", "error")
            return redirect(url_for("home"))

        return view_function(*args, **kwargs)

    return wrapper


# =========================================================
# WORKSPACE HELPERS
# =========================================================

def current_owner_id():
    """
    Regular users work with their own student records.

    The root administrator can select another user's workspace.
    """

    if session.get("is_root", False):
        return session.get(
            "workspace_user_id",
            session["admin_id"]
        )

    return session["admin_id"]


def current_workspace_username():
    if session.get("is_root", False):
        return session.get(
            "workspace_username",
            session.get("admin_username", "")
        )

    return session.get("admin_username", "")


def user_owns_student(cursor, student_id):
    cursor.execute(
        """
        SELECT id
        FROM students
        WHERE id = %s
          AND owner_user_id = %s
        """,
        (student_id, current_owner_id())
    )

    return cursor.fetchone() is not None


# =========================================================
# FORM VALIDATION
# =========================================================

def _student_form_values():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    course = request.form.get("course", "").strip()
    age_text = request.form.get("age", "").strip()

    if len(name) < 2 or len(name) > 100:
        return None, "Name must contain between 2 and 100 characters."

    if len(email) > 100:
        return None, "Email must not exceed 100 characters."

    if email and not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email
    ):
        return None, "Please enter a valid email address."

    if phone and not re.fullmatch(r"[0-9+\-\s()]{7,15}", phone):
        return None, "Please enter a valid phone number."

    if not course or len(course) > 100:
        return None, "Course is required and must not exceed 100 characters."

    try:
        age = int(age_text)
    except (TypeError, ValueError):
        return None, "Age must be a valid number."

    if age < 1 or age > 100:
        return None, "Age must be between 1 and 100."

    return {
        "name": name,
        "email": email or None,
        "phone": phone or None,
        "course": course,
        "age": age,
    }, None


def _fee_form_values():
    total_text = request.form.get("total_fee", "").strip()
    paid_text = request.form.get("paid_amount", "0").strip()

    try:
        total_fee = Decimal(total_text)
        paid_amount = Decimal(paid_text or "0")
    except (InvalidOperation, ValueError):
        return None, "Enter valid numeric values for the fees."

    if not total_fee.is_finite() or not paid_amount.is_finite():
        return None, "Fee values must be valid numbers."

    if total_fee < 0 or paid_amount < 0:
        return None, "Fee amounts cannot be negative."

    if total_fee > Decimal("99999999.99"):
        return None, "Total fee is too large."

    if paid_amount > total_fee:
        return None, "Paid amount cannot exceed the total fee."

    for amount in (total_fee, paid_amount):
        if amount.as_tuple().exponent < -2:
            return None, "Fee amounts can have a maximum of two decimal places."

    return {
        "total_fee": total_fee,
        "paid_amount": paid_amount,
    }, None


def save_student_fees(cursor, student_id, total_fee, paid_amount):
    """
    Create or update the fee record for a student.

    This uses the existing student_fees table, where student_id
    is unique and total_fee and paid_amount are stored.
    """

    cursor.execute(
        """
        INSERT INTO student_fees
            (student_id, total_fee, paid_amount)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
            total_fee = VALUES(total_fee),
            paid_amount = VALUES(paid_amount),
            updated_at = CURRENT_TIMESTAMP
        """,
        (student_id, total_fee, paid_amount)
    )


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if "admin_id" in session:
        if session.get("is_root", False):
            return redirect(url_for("manage_users"))

        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = None
        cursor = None

        try:
            connection = get_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT id, username, password_hash, role, is_root
                FROM admins
                WHERE username = %s
                LIMIT 1
                """,
                (username,)
            )

            admin = cursor.fetchone()

            if admin and check_password_hash(admin[2], password):
                session.clear()

                session["admin_id"] = admin[0]
                session["admin_username"] = admin[1]
                session["admin_role"] = admin[3]
                session["is_root"] = bool(admin[4])

                if session["is_root"]:
                    session["workspace_user_id"] = admin[0]
                    session["workspace_username"] = admin[1]

                    flash("Welcome, root administrator.", "success")
                    return redirect(url_for("manage_users"))

                flash("Login successful.", "success")
                return redirect(url_for("home"))

            flash("Invalid username or password.", "error")

        except Exception as error:
            app.logger.exception("Login error: %s", error)
            flash("Unable to log in. Please check the database connection.", "error")

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    return render_template("login.html")


# =========================================================
# CREATE STAFF ACCOUNT
# =========================================================

def _create_staff_account():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not re.fullmatch(r"[A-Za-z0-9_]{3,50}", username):
        return False, (
            "Username must contain 3-50 characters using "
            "letters, numbers, or underscores."
        )

    if len(password) < 8:
        return False, "Password must contain at least 8 characters."

    if password != confirm_password:
        return False, "Passwords do not match."

    password_hash = generate_password_hash(password)

    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Public registration can create staff accounts only.
        # Users cannot promote themselves to admin or root.
        cursor.execute(
            """
            INSERT INTO admins
                (username, password_hash, role, is_root)
            VALUES (%s, %s, %s, %s)
            """,
            (username, password_hash, "staff", 0)
        )

        connection.commit()

        return True, "User account created successfully."

    except Exception as error:
        if connection:
            connection.rollback()

        # MySQL duplicate-key error.
        if getattr(error, "args", [None])[0] == 1062:
            return False, "That username already exists."

        app.logger.exception("Account creation error: %s", error)
        return False, "Unable to create the account. Please check the database."

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# PUBLIC REGISTRATION
# =========================================================

@app.route("/register-user", methods=["GET", "POST"])
def register_user():
    if "admin_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        success, message = _create_staff_account()

        if success:
            flash(message + " Please log in.", "success")
            return redirect(url_for("login"))

        flash(message, "error")

    return render_template(
        "register_user.html",
        root_flow=False
    )


# =========================================================
# ROOT-ONLY USER CREATION
# =========================================================

@app.route("/create-user", methods=["GET", "POST"])
@root_required
def create_user():
    if request.method == "POST":
        success, message = _create_staff_account()

        if success:
            flash(message, "success")
            return redirect(url_for("manage_users"))

        flash(message, "error")

    return render_template(
        "register_user.html",
        root_flow=True
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# =========================================================
# MANAGE USERS
# =========================================================

@app.route("/manage-users")
@root_required
def manage_users():
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, username, role, is_root
            FROM admins
            ORDER BY id ASC
            """
        )

        users = cursor.fetchall()

        return render_template(
            "manage_users.html",
            users=users,
            selected_user_id=current_owner_id()
        )

    except Exception as error:
        app.logger.exception("Manage users error: %s", error)
        flash("Unable to load the user list.", "error")
        return redirect(url_for("home"))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# SELECT USER WORKSPACE
# =========================================================

@app.route("/select-workspace/<int:user_id>", methods=["POST"])
@root_required
def select_workspace(user_id):
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, username
            FROM admins
            WHERE id = %s
            LIMIT 1
            """,
            (user_id,)
        )

        selected_user = cursor.fetchone()

        if not selected_user:
            flash("The selected user does not exist.", "error")
            return redirect(url_for("manage_users"))

        session["workspace_user_id"] = selected_user[0]
        session["workspace_username"] = selected_user[1]

        flash(
            "Workspace changed to " + selected_user[1] + ".",
            "success"
        )

        return redirect(url_for("manage_users"))

    except Exception as error:
        app.logger.exception("Workspace selection error: %s", error)
        flash("Unable to select the workspace.", "error")
        return redirect(url_for("manage_users"))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
@login_required
def home():
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        owner_id = current_owner_id()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM students
            WHERE owner_user_id = %s
            """,
            (owner_id,)
        )
        total_students = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(DISTINCT course)
            FROM students
            WHERE owner_user_id = %s
            """
            ,
            (owner_id,)
        )
        total_courses = cursor.fetchone()[0]

        return render_template(
            "home.html",
            total_students=total_students,
            total_courses=total_courses,
            is_root=session.get("is_root", False),
            workspace_username=current_workspace_username()
        )

    except Exception as error:
        app.logger.exception("Dashboard error: %s", error)
        flash("Unable to load the dashboard.", "error")
        return render_template(
            "home.html",
            total_students=0,
            total_courses=0,
            is_root=session.get("is_root", False),
            workspace_username=current_workspace_username()
        )

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# STUDENT LIST AND SEARCH
# =========================================================

@app.route("/students")
@login_required
def students():
    search = request.args.get("search", "").strip()

    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        owner_id = current_owner_id()

        query = """
            SELECT
                s.id,
                s.name,
                s.email,
                s.phone,
                s.course,
                s.age,
                COALESCE(f.total_fee, 50000.00) AS total_fee,
                COALESCE(f.paid_amount, 0.00) AS paid_amount,
                (
                    COALESCE(f.total_fee, 50000.00)
                    - COALESCE(f.paid_amount, 0.00)
                ) AS balance,
                CASE
                    WHEN COALESCE(f.paid_amount, 0) = 0
                        THEN 'Pending'
                    WHEN COALESCE(f.paid_amount, 0)
                         >= COALESCE(f.total_fee, 50000)
                        THEN 'Paid'
                    ELSE 'Partial'
                END AS fee_status
            FROM students s
            LEFT JOIN student_fees f
                ON f.student_id = s.id
            WHERE s.owner_user_id = %s
        """

        parameters = [owner_id]

        if search:
            query += """
                AND (
                    s.name LIKE %s
                    OR s.email LIKE %s
                    OR s.phone LIKE %s
                    OR s.course LIKE %s
                )
            """

            search_value = "%" + search + "%"
            parameters.extend([
                search_value,
                search_value,
                search_value,
                search_value
            ])

        query += " ORDER BY s.id DESC"

        cursor.execute(query, tuple(parameters))
        student_records = cursor.fetchall()

        return render_template(
            "students.html",
            students=student_records,
            search=search,
            page=1,
            total_pages=1,
            is_admin=session.get("admin_role") == "admin",
            is_root=session.get("is_root", False),
            workspace_username=current_workspace_username()
        )

    except Exception as error:
        app.logger.exception("Student list error: %s", error)
        flash("Unable to load student records.", "error")

        return render_template(
            "students.html",
            students=[],
            search=search,
            page=1,
            total_pages=1,
            is_admin=session.get("admin_role") == "admin",
            is_root=session.get("is_root", False),
            workspace_username=current_workspace_username()
        )

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# ADD STUDENT
# =========================================================

@app.route("/add-student", methods=["GET", "POST"])
@login_required
def add_student():
    if request.method == "POST":
        values, error_message = _student_form_values()

        if error_message:
            flash(error_message, "error")
            return render_template("add_student.html")

        connection = None
        cursor = None

        try:
            connection = get_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO students
                    (name, email, phone, course, age, owner_user_id)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    values["name"],
                    values["email"],
                    values["phone"],
                    values["course"],
                    values["age"],
                    current_owner_id()
                )
            )

            student_id = cursor.lastrowid

            # New students receive the default fee record.
            save_student_fees(
                cursor,
                student_id,
                Decimal("50000.00"),
                Decimal("0.00")
            )

            connection.commit()

            flash("Student added successfully.", "success")
            return redirect(url_for("students"))

        except Exception as error:
            if connection:
                connection.rollback()

            if getattr(error, "args", [None])[0] == 1062:
                flash("This email address is already being used.", "error")
            else:
                app.logger.exception("Add student error: %s", error)
                flash("Unable to add the student.", "error")

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    return render_template("add_student.html")


# =========================================================
# EDIT STUDENT
# Supports both edit-student and update-student URLs.
# =========================================================

@app.route(
    "/edit-student/<int:id>",
    methods=["GET", "POST"],
    endpoint="edit_student"
)
@app.route(
    "/update-student/<int:id>",
    methods=["GET", "POST"],
    endpoint="update_student"
)
@login_required
def edit_student(id):
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                s.id,
                s.name,
                s.email,
                s.phone,
                s.course,
                s.age,
                COALESCE(f.total_fee, 50000.00),
                COALESCE(f.paid_amount, 0.00)
            FROM students s
            LEFT JOIN student_fees f
                ON f.student_id = s.id
            WHERE s.id = %s
              AND s.owner_user_id = %s
            LIMIT 1
            """,
            (id, current_owner_id())
        )

        student = cursor.fetchone()

        if not student:
            flash("Student not found in the selected workspace.", "error")
            return redirect(url_for("students"))

        is_admin = session.get("admin_role") == "admin"

        if request.method == "POST":
            values, error_message = _student_form_values()

            if error_message:
                flash(error_message, "error")
                return render_template(
                    "edit_student.html",
                    student=student,
                    total_fee=student[6],
                    paid_amount=student[7],
                    is_admin=is_admin
                )

            fee_values = None

            if is_admin:
                fee_values, error_message = _fee_form_values()

                if error_message:
                    flash(error_message, "error")
                    return render_template(
                        "edit_student.html",
                        student=student,
                        total_fee=student[6],
                        paid_amount=student[7],
                        is_admin=is_admin
                    )

            cursor.execute(
                """
                UPDATE students
                SET name = %s,
                    email = %s,
                    phone = %s,
                    course = %s,
                    age = %s
                WHERE id = %s
                  AND owner_user_id = %s
                """,
                (
                    values["name"],
                    values["email"],
                    values["phone"],
                    values["course"],
                    values["age"],
                    id,
                    current_owner_id()
                )
            )

            if is_admin and fee_values:
                save_student_fees(
                    cursor,
                    id,
                    fee_values["total_fee"],
                    fee_values["paid_amount"]
                )

            connection.commit()

            flash("Student information updated successfully.", "success")
            return redirect(url_for("students"))

        return render_template(
            "edit_student.html",
            student=student,
            total_fee=student[6],
            paid_amount=student[7],
            is_admin=is_admin
        )

    except Exception as error:
        if connection:
            connection.rollback()

        if getattr(error, "args", [None])[0] == 1062:
            flash("This email address is already being used.", "error")
        else:
            app.logger.exception("Edit student error: %s", error)
            flash("Unable to update the student.", "error")

        return redirect(url_for("students"))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# UPDATE FEES (ADMIN ONLY)
# =========================================================

@app.route("/update-fees/<int:id>", methods=["GET", "POST"])
@login_required
@role_required("admin")
def update_fees(id):
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, name
            FROM students
            WHERE id = %s
              AND owner_user_id = %s
            LIMIT 1
            """,
            (id, current_owner_id())
        )

        student = cursor.fetchone()

        if not student:
            flash("Student not found in the selected workspace.", "error")
            return redirect(url_for("students"))

        cursor.execute(
            """
            SELECT total_fee, paid_amount
            FROM student_fees
            WHERE student_id = %s
            LIMIT 1
            """,
            (id,)
        )

        fee_record = cursor.fetchone()

        total_fee = fee_record[0] if fee_record else Decimal("50000.00")
        paid_amount = fee_record[1] if fee_record else Decimal("0.00")

        if request.method == "POST":
            fee_values, error_message = _fee_form_values()

            if error_message:
                flash(error_message, "error")
            else:
                save_student_fees(
                    cursor,
                    id,
                    fee_values["total_fee"],
                    fee_values["paid_amount"]
                )

                connection.commit()

                flash("Student fees updated successfully.", "success")
                return redirect(url_for("students"))

        # Uses the existing edit form to avoid requiring a new template.
        cursor.execute(
            """
            SELECT id, name, email, phone, course, age
            FROM students
            WHERE id = %s
              AND owner_user_id = %s
            LIMIT 1
            """,
            (id, current_owner_id())
        )

        student_details = cursor.fetchone()

        return render_template(
            "edit_student.html",
            student=student_details,
            total_fee=total_fee,
            paid_amount=paid_amount,
            is_admin=True,
            fee_only=True
        )

    except Exception as error:
        if connection:
            connection.rollback()

        app.logger.exception("Update fees error: %s", error)
        flash("Unable to update student fees.", "error")
        return redirect(url_for("students"))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# DELETE STUDENT (ADMIN ONLY)
# =========================================================

@app.route("/delete-student/<int:id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_student(id):
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id
            FROM students
            WHERE id = %s
              AND owner_user_id = %s
            LIMIT 1
            """,
            (id, current_owner_id())
        )

        if not cursor.fetchone():
            flash("Student not found in the selected workspace.", "error")
            return redirect(url_for("students"))

        # Delete fee information before deleting the student.
        cursor.execute(
            "DELETE FROM student_fees WHERE student_id = %s",
            (id,)
        )

        cursor.execute(
            """
            DELETE FROM students
            WHERE id = %s
              AND owner_user_id = %s
            """,
            (id, current_owner_id())
        )

        connection.commit()

        flash("Student deleted successfully.", "success")

    except Exception as error:
        if connection:
            connection.rollback()

        app.logger.exception("Delete student error: %s", error)
        flash("Unable to delete the student.", "error")

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect(url_for("students"))


# =========================================================
# COURSE REPORT
# =========================================================

@app.route("/course-report")
@login_required
def course_report():
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT course, COUNT(*) AS student_count
            FROM students
            WHERE owner_user_id = %s
            GROUP BY course
            ORDER BY course ASC
            """,
            (current_owner_id(),)
        )

        course_data = cursor.fetchall()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM students
            WHERE owner_user_id = %s
            """,
            (current_owner_id(),)
        )

        total_students = cursor.fetchone()[0]

        total_courses = len(course_data)

        return render_template(
            "course_report.html",
            course_data=course_data,
            courses=course_data,
            total_students=total_students,
            total_courses=total_courses,
            workspace_username=current_workspace_username()
        )

    except Exception as error:
        app.logger.exception("Course report error: %s", error)
        flash("Unable to load the course report.", "error")
        return redirect(url_for("home"))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# EXPORT STUDENTS TO EXCEL
# =========================================================

@app.route("/export-students")
@login_required
def export_students():
    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                s.id AS Student_ID,
                s.name AS Name,
                s.email AS Email,
                s.phone AS Phone,
                s.course AS Course,
                s.age AS Age,
                COALESCE(f.total_fee, 50000.00) AS Total_Fee,
                COALESCE(f.paid_amount, 0.00) AS Paid_Amount,
                (
                    COALESCE(f.total_fee, 50000.00)
                    - COALESCE(f.paid_amount, 0.00)
                ) AS Balance
            FROM students s
            LEFT JOIN student_fees f
                ON f.student_id = s.id
            WHERE s.owner_user_id = %s
            ORDER BY s.id ASC
            """,
            (current_owner_id(),)
        )

        records = cursor.fetchall()

        columns = [
            "Student_ID",
            "Name",
            "Email",
            "Phone",
            "Course",
            "Age",
            "Total_Fee",
            "Paid_Amount",
            "Balance"
        ]

        dataframe = pd.DataFrame(records, columns=columns)

        output = BytesIO()

        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            dataframe.to_excel(
                writer,
                index=False,
                sheet_name="Students"
            )

        output.seek(0)

        return send_file(
            output,
            as_attachment=True,
            download_name="student_records.xlsx",
            mimetype=(
                "application/vnd.openxmlformats-officedocument."
                "spreadsheetml.sheet"
            )
        )

    except Exception as error:
        app.logger.exception("Excel export error: %s", error)
        flash("Unable to export student records.", "error")
        return redirect(url_for("students"))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# =========================================================
# CHANGE PASSWORD
# =========================================================

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(new_password) < 8:
            flash("New password must contain at least 8 characters.", "error")
            return render_template("change_password.html")

        if new_password != confirm_password:
            flash("New passwords do not match.", "error")
            return render_template("change_password.html")

        connection = None
        cursor = None

        try:
            connection = get_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT password_hash
                FROM admins
                WHERE id = %s
                LIMIT 1
                """,
                (session["admin_id"],)
            )

            account = cursor.fetchone()

            if not account or not check_password_hash(
                account[0],
                current_password
            ):
                flash("Current password is incorrect.", "error")
                return render_template("change_password.html")

            new_hash = generate_password_hash(new_password)

            cursor.execute(
                """
                UPDATE admins
                SET password_hash = %s
                WHERE id = %s
                """,
                (new_hash, session["admin_id"])
            )

            connection.commit()

            flash("Password changed successfully.", "success")
            return redirect(url_for("home"))

        except Exception as error:
            if connection:
                connection.rollback()

            app.logger.exception("Change password error: %s", error)
            flash("Unable to change your password.", "error")

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    return render_template("change_password.html")


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)