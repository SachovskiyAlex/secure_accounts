import sqlite3

def init_db(path="database.db"):
    conn = sqlite3.connect(path)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 0,
        is_2fa_enabled INTEGER NOT NULL DEFAULT 0,
        failed_logins INTEGER NOT NULL DEFAULT 0,
        lock_until TEXT,
        activation_token TEXT,
        reset_token TEXT,
        reset_token_expires_at TEXT,
        oauth_provider TEXT,
        oauth_id TEXT,
        twofa_code TEXT,
        twofa_exp TEXT
    );
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username_or_email TEXT,
        ip_address TEXT,
        timestamp TEXT,
        success INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
