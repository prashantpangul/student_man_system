import mysql.connector

print("START")

connection = mysql.connector.connect(
    host="127.0.0.1",
    port=3306,
    user="root",
    password="root",
    connection_timeout=5
)

print("MYSQL CONNECTION SUCCESSFUL")

connection.close()