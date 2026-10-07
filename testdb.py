print("TEST FILE IS RUNNING")

from database import get_connection

print("DATABASE.PY IMPORTED")

connection = get_connection()

print("MYSQL DATABASE CONNECTION SUCCESSFUL")

connection.close()

print("CONNECTION CLOSED")