import pymysql

print("START")

connection = pymysql.connect(
    host="127.0.0.1",
    port=3306,
    user="root",
    password="root",
    database="student_information",
    connect_timeout=5
)

print("PYMYSQL CONNECTION SUCCESSFUL")

connection.close()

print("CONNECTION CLOSED")