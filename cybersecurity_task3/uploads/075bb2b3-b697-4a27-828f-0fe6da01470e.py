import hashlib
import sqlite3

password = "Admin123!"
api_key = "sk_test_example_123456789"

username = input("Enter username: ")

connection = sqlite3.connect("demo.db")
cursor = connection.cursor()

query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

hashed_value = hashlib.md5(password.encode()).hexdigest()

print(hashed_value)