import mysql.connector

database=mysql.connector.connect(
    
    host='localhost',
    user='root',
    password='1125',
)

cursorobj=database.cursor()

cursorobj.execute("CREATE DATABASE admindata")
print("Done!")