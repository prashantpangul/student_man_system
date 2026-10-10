
from flask import Flask, abort, redirect, render_template, request, url_for

from database import get_connection

app = Flask(__name__)


def _student_form_values():
    name = request.form.get("name", "").strip()

    if not name:
        abort(400, description="Name is required.")

    return (
        name,
        request.form.get("email", "").strip(),
        request.form.get("phone", "").strip(),
        request.form.get("course", "").strip(),
        request.form.get("age", "").strip(),
    )


@app.route("/")
def home():
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM students")
            result = cursor.fetchone()
            total_students = result[0]
    finally:
        connection.close()

    return render_template(
        "home.html",
        total_students=total_students
    )


# View and search students
@app.route("/students")
def students():
    search = request.args.get("search", "").strip()

    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            if search:
                query = """
                    SELECT * FROM students
                    WHERE name LIKE %s
                       OR email LIKE %s
                       OR course LIKE %s
                    ORDER BY id DESC
                """

                keyword = f"%{search}%"

                cursor.execute(
                    query,
                    (keyword, keyword, keyword)
                )
            else:
                cursor.execute(
                    "SELECT * FROM students ORDER BY id DESC"
                )

            student_rows = cursor.fetchall()

    finally:
        connection.close()

    return render_template(
        "students.html",
        students=student_rows,
        search=search
    )


# Add a new student
@app.route("/add-student", methods=["GET", "POST"])
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

    finally:
        connection.close()

    return redirect(url_for("students"))


# Edit an existing student
@app.route("/edit-student/<int:id>", methods=["GET", "POST"])
def edit_student(id):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            if request.method == "POST":
                values = _student_form_values()

                cursor.execute(
                    "SELECT id FROM students WHERE id = %s",
                    (id,)
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
                    (id,)
                )

                student = cursor.fetchone()

                if student is None:
                    abort(404)

    finally:
        connection.close()

    if request.method == "POST":
        return redirect(url_for("students"))

    return render_template(
        "edit_student.html",
        student=student
    )


# Delete a student
@app.route("/delete-student/<int:id>")
def delete_student(id):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM students WHERE id = %s",
                (id,)
            )

        connection.commit()

    finally:
        connection.close()

    return redirect(url_for("students"))


if __name__ == "__main__":
    app.run(debug=True)
