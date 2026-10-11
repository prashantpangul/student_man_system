
from getpass import getpass
from werkzeug.security import generate_password_hash

from database import get_connection


def setup_admin():
    username = input("Enter admin username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    password = getpass("Enter admin password: ")
    confirm_password = getpass("Confirm admin password: ")

    if len(password) < 8:
        print("Password must contain at least 8 characters.")
        return

    if password != confirm_password:
        print("Passwords do not match.")
        return

    password_hash = generate_password_hash(password)
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM admins WHERE username = %s",
                (username,)
            )

            existing_admin = cursor.fetchone()

            if existing_admin:
                print("This username already exists.")
                return

            cursor.execute(
                """
                INSERT INTO admins (username, password_hash)
                VALUES (%s, %s)
                """,
                (username, password_hash)
            )

        connection.commit()
        print("Admin account created successfully!")

    except Exception as error:
        connection.rollback()
        print("Could not create admin account:", error)

    finally:
        connection.close()


if __name__ == "__main__":
    setup_admin()
