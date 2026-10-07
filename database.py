import pymysql


def get_connection():
    connection = pymysql.connect(
        host="127.0.0.1",
        port=3306,
        user="root",
        password="root",
        database="student_information",
        connect_timeout=5
    )

    return connection