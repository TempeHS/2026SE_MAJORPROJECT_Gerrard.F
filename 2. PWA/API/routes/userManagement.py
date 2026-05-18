import sqlite3 as sql
import bcrypt

db_path = "../databases/users/users.db"


def insertUser(username, email, password):
    con = sql.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT username, email FROM users WHERE email = ? OR username = ?", (email, username))
    user = cur.fetchone()
    if user:
        if user[1]:
            return False, "Email already registered"
        else:
            return False, "Username already registered"
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    cur.execute(
        "INSERT INTO users (username, email, password) VALUES (?,?,?)", (username, email, hashed_password)
    )
    con.commit()
    con.close()
    return True


def loginUser(identity, password):
    con = sql.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT id, password FROM users WHERE email = ? OR username = ?", (identity, identity))
    user = cur.fetchone()
    con.close()

    if user is None:
        return None

    if bcrypt.checkpw(password.encode("utf-8"), user[1]):
        return user[0]


