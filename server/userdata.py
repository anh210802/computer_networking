import sqlite3
import hashlib

conn = sqlite3.connect("filename_of_users.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS filename_of_users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    port VARCHAR(255) NOT NULL
)
""")

username1, filename1, hostname1, port1 = "client1", "file.txt", "127.0.0.1", "12"


cur.execute("INSERT INTO filename_of_users (username,filename,hostname,port) VALUES (?, ?, ?, ?)", (username1, filename1, hostname1, port1))


conn.commit()