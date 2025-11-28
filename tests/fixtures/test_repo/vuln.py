import sqlite3

def search_users(query):
    # SQL injection vulnerability
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(sql)  # VULNERABLE
    return cursor.fetchall()

def bad_eval(user_input):
    # Code injection
    result = eval(user_input)  # VULNERABLE
    return result
