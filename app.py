from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from elasticsearch import Elasticsearch
import json
import os
import sqlite3
import bcrypt
from datetime import datetime
from functools import wraps

app = Flask(__name__)
# Load secret key from environment or generate a warning
secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    import secrets
    secret_key = secrets.token_hex(32)
    print("WARNING: No SECRET_KEY environment variable set. Using randomly generated key.")
    print("Sessions will be invalidated on restart. Set SECRET_KEY for production!")
app.secret_key = secret_key

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER")
ES_PASSWORD = os.getenv("ES_PASSWORD")

if ES_USER and ES_PASSWORD:
    es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))
else:
    es = Elasticsearch(ES_HOST)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Database setup
DB_PATH = "search.db"


def init_db():
    """Initialize database with tables and default admin"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Audit logs table
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            query TEXT NOT NULL,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            results_count INTEGER,
            results_summary TEXT,
            took_ms INTEGER,
            error TEXT
        )
    """)
    
    # Create default admin if not exists
    c.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not c.fetchone():
        # Default password: admin123 (should be changed after first login)
        password_hash = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                  ("admin", password_hash, 1))
    
    conn.commit()
    conn.close()


# Initialize database on startup
init_db()


class User(UserMixin):
    def __init__(self, id, username, is_admin):
        self.id = id
        self.username = username
        self.is_admin = is_admin


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return User(row[0], row[1], row[2])
    return None


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("需要管理员权限", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


def log_audit(username, query, ip_address, results_count=None, results_summary=None, took_ms=None, error=None):
    """Log search query to audit table"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO audit_logs (username, query, ip_address, results_count, results_summary, took_ms, error)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (username, query, ip_address, results_count, results_summary, took_ms, error))
    conn.commit()
    conn.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("请输入用户名和密码", "error")
            return render_template("login.html")
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        
        if row and bcrypt.checkpw(password.encode('utf-8'), row[2]):
            user = User(row[0], row[1], row[3])
            login_user(user)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))
        else:
            flash("用户名或密码错误", "error")
    
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
@login_required
def index():
    q = request.args.get("q", "").strip()
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 10))
    page = max(page, 1)
    size = min(max(size, 1), 100)
    from_ = (page - 1) * size

    results = None
    error = None

    if q:
        try:
            body = {
                "track_total_hits": True,
                "from": from_,
                "size": size,
                "query": {
                    "simple_query_string": {
                        "query": q,
                        "fields": ["*"],
                        "default_operator": "and"
                    }
                },
                "highlight": {
                    "fields": {
                        "*": {
                            "pre_tags": ["<mark>"],
                            "post_tags": ["</mark>"],
                            "number_of_fragments": 3,
                            "fragment_size": 150
                        }
                    }
                }
            }
            resp = es.search(index="*", body=body)
            results = resp
            
            # Log audit
            results_count = results.get("hits", {}).get("total", {}).get("value", 0)
            took_ms = results.get("took", 0)
            # Create summary with first few results
            summary_items = []
            for hit in results.get("hits", {}).get("hits", [])[:3]:
                summary_items.append(f"{hit.get('_index')}:{hit.get('_id')}")
            results_summary = ", ".join(summary_items) if summary_items else "无结果"
            
            log_audit(
                username=current_user.username,
                query=q,
                ip_address=request.remote_addr,
                results_count=results_count,
                results_summary=results_summary,
                took_ms=took_ms
            )
        except Exception as exc:
            error = str(exc)
            log_audit(
                username=current_user.username,
                query=q,
                ip_address=request.remote_addr,
                error=error
            )

    return render_template(
        "index.html",
        q=q,
        results=results,
        error=error,
        page=page,
        size=size
    )


@app.route("/admin")
@login_required
@admin_required
def admin():
    """Admin dashboard"""
    return render_template("admin.html")


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    """List all users"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC")
    users = [{"id": row[0], "username": row[1], "is_admin": row[2], "created_at": row[3]} for row in c.fetchall()]
    conn.close()
    return jsonify(users)


@app.route("/admin/users/add", methods=["POST"])
@login_required
@admin_required
def admin_add_user():
    """Add new user"""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    is_admin = 1 if request.form.get("is_admin") == "on" else 0
    
    if not username or not password:
        return jsonify({"success": False, "error": "用户名和密码不能为空"}), 400
    
    if len(password) < 6:
        return jsonify({"success": False, "error": "密码长度至少6位"}), 400
    
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                  (username, password_hash, is_admin))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "用户名已存在"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_delete_user(user_id):
    """Delete user"""
    if user_id == current_user.id:
        return jsonify({"success": False, "error": "不能删除自己"}), 400
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Check if user to delete is an admin
    c.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if row and row[0]:
        # Count remaining admins
        c.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        admin_count = c.fetchone()[0]
        if admin_count <= 1:
            conn.close()
            return jsonify({"success": False, "error": "不能删除最后一个管理员账号"}), 400
    
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
@admin_required
def admin_reset_password(user_id):
    """Reset user password"""
    new_password = request.form.get("password", "")
    
    if not new_password or len(new_password) < 6:
        return jsonify({"success": False, "error": "密码长度至少6位"}), 400
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/admin/change-password", methods=["POST"])
@login_required
def change_password():
    """Change current user's password"""
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    
    if not old_password or not new_password:
        return jsonify({"success": False, "error": "请填写完整"}), 400
    
    if len(new_password) < 6:
        return jsonify({"success": False, "error": "新密码长度至少6位"}), 400
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE id = ?", (current_user.id,))
    row = c.fetchone()
    
    if not row or not bcrypt.checkpw(old_password.encode('utf-8'), row[0]):
        conn.close()
        return jsonify({"success": False, "error": "原密码错误"}), 400
    
    password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route("/admin/audit-logs")
@login_required
@admin_required
def admin_audit_logs():
    """Get audit logs"""
    page = int(request.args.get("page", 1))
    per_page = 50
    offset = (page - 1) * per_page
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get total count
    c.execute("SELECT COUNT(*) FROM audit_logs")
    total = c.fetchone()[0]
    
    # Get logs
    c.execute("""
        SELECT id, username, query, ip_address, timestamp, results_count, results_summary, took_ms, error
        FROM audit_logs
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    
    logs = []
    for row in c.fetchall():
        logs.append({
            "id": row[0],
            "username": row[1],
            "query": row[2],
            "ip_address": row[3],
            "timestamp": row[4],
            "results_count": row[5],
            "results_summary": row[6],
            "took_ms": row[7],
            "error": row[8]
        })
    
    conn.close()
    
    return jsonify({
        "logs": logs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    })


@app.template_filter("tojson_pretty")
def tojson_pretty(value):
    return json.dumps(value, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)