import mysql.connector

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="capstone_web"
)

cursor = db.cursor(dictionary=True)
