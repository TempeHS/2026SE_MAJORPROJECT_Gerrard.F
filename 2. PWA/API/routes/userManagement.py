import sqlite3 as sql
import bcrypt

db_path = "../databases/users/users.db"


def insertUser(name, email, password):
    con = sql.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT email FROM users WHERE email = ?", (email,name))
    user = cur.fetchone()
    if user:
        if user[0]:
            return False, "Email already registered"
        else:
            return False, "User already registered"
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    cur.execute(
        "INSERT INTO users (name, email, password) VALUES (?,?,?)", (name, email, hashed_password)
    )
    con.commit()
    con.close()
    return True


def loginUser(email, password):
    con = sql.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT password FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    con.close()

    if user is None:
        return None

    hashed_password = user[0]
    if bcrypt.checkpw(password.encode("utf-8"), hashed_password):
        con = sql.connect(db_path)
        cur = con.cursor()
        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        user_result = cur.fetchone()
        con.close()
        return user_result[0]


