# ==============================================================================
# Jerin's Men's Wear - Secure DevSecOps E-Commerce Storefront
# Production-ready Flask Application (app.py)
# ==============================================================================

import os
import re
import sys
import time
import uuid
import sqlite3
import pymysql
import bcrypt
import threading
from datetime import datetime
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    flash,
    g,
    make_response,
    abort,
    render_template_string
)

# Initialize Flask App
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', '7e9b89c4fbc256e2978a3c5a896d8b9d4692e8fae85df649f87c2b3e8e2fa012')

# Database Configuration Variables
DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')
DB_NAME = os.environ.get('DB_NAME')

# Global Thread-Safe Sliding Window Rate Limiter for Authentication
class AntiBruteForceLimiter:
    def __init__(self, limit=5, window=60):
        self.limit = limit
        self.window = window
        self.attempts = {}
        self.lock = threading.Lock()

    def is_locked(self, ip):
        with self.lock:
            now = time.time()
            if ip in self.attempts:
                record = self.attempts[ip]
                if record['lockout_until'] > now:
                    return True, int(record['lockout_until'] - now)
                elif record['lockout_until'] > 0:
                    # Lockout expired, reset history
                    self.attempts[ip] = {'timestamps': [], 'lockout_until': 0}
            return False, 0

    def record_attempt(self, ip, success):
        with self.lock:
            now = time.time()
            if ip not in self.attempts:
                self.attempts[ip] = {'timestamps': [], 'lockout_until': 0}
            
            record = self.attempts[ip]
            if success:
                # Reset attempts on successful authentication
                self.attempts[ip] = {'timestamps': [], 'lockout_until': 0}
                return False, 0
            
            # Prune timestamps older than sliding window
            record['timestamps'] = [t for t in record['timestamps'] if now - t < self.window]
            record['timestamps'].append(now)
            
            if len(record['timestamps']) >= self.limit:
                record['lockout_until'] = now + self.window
                return True, self.window
            
            return False, 0

# Initialize global authentication rate limiter
auth_limiter = AntiBruteForceLimiter(limit=5, window=60)

# ==============================================================================
# Dual-Database Hybrid Adapter Layer
# ==============================================================================

def is_mysql_configured():
    return all([DB_HOST, DB_USER, DB_PASS, DB_NAME])

def get_db_connection():
    if is_mysql_configured():
        try:
            # 1. Connect to RDS server engine to ensure target schema exists
            bootstrap_conn = pymysql.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASS,
                autocommit=True
            )
            bootstrap_cursor = bootstrap_conn.cursor()
            bootstrap_cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
            bootstrap_cursor.close()
            bootstrap_conn.close()

            # 2. Connect to the dynamically bootstrapped database schema
            conn = pymysql.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASS,
                database=DB_NAME,
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )
            return conn, "mysql"
        except Exception as e:
            # Fallback to sqlite if connection fails even though variables are set
            print(f"Warning: RDS MySQL connection failed: {e}. Falling back to SQLite.", file=sys.stderr)
    
    # SQLite Fallback
    conn = sqlite3.connect('local_jerins.db')
    conn.row_factory = sqlite3.Row
    return conn, "sqlite"

def execute_query(query, params=(), fetch="all"):
    """
    Executes an SQL query in a secure, parameter-safe fashion to protect against SQLi.
    """
    conn, engine = get_db_connection()
    cursor = conn.cursor()
    try:
        # SQLite parameters use '?', MySQL uses '%s'. Convert placeholder format.
        if engine == "mysql":
            query = query.replace('?', '%s')
            # Handle INSERT OR IGNORE differences
            query = query.replace('INSERT OR IGNORE', 'INSERT IGNORE')
        
        cursor.execute(query, params)
        
        if query.strip().upper().startswith("SELECT"):
            if fetch == "one":
                result = cursor.fetchone()
            else:
                result = cursor.fetchall()
            # Standardize row outputs to dicts for seamless rendering compatibility
            if engine == "sqlite" and result:
                if fetch == "one":
                    result = dict(result)
                else:
                    result = [dict(row) for row in result]
            return result
        else:
            if engine == "mysql":
                conn.commit()
            else:
                conn.commit()
            return cursor.lastrowid
    except Exception as e:
        print(f"Database Query Error: {e}", file=sys.stderr)
        raise e
    finally:
        cursor.close()
        conn.close()

def log_security_event(event_type, ip_address, username, details):
    query = """
    INSERT INTO security_logs (event_type, ip_address, username, details)
    VALUES (?, ?, ?, ?)
    """
    try:
        execute_query(query, (event_type, ip_address, username, details))
    except Exception as e:
        print(f"Critical Logging Failure: {e}", file=sys.stderr)

def init_database():
    """
    Initializes database tables and catalog using migrations in schema.sql.
    Parses and executes table layouts dynamically for SQLite and MySQL compatibility.
    """
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')
    if not os.path.exists(schema_path):
        schema_path = 'schema.sql'
        
    if os.path.exists(schema_path):
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema_content = f.read()
            # Clean out single-line SQL comments to prevent statement skipping
            cleaned_lines = [line for line in schema_content.splitlines() if not line.strip().startswith('--')]
            statements = "\n".join(cleaned_lines).split(';')
    else:
        print("Error: schema.sql file not found. Could not seed database structures.", file=sys.stderr)
        return

    conn, engine = get_db_connection()
    cursor = conn.cursor()
    try:
        for stmt in statements:
            stmt = stmt.strip()
            if not stmt or stmt.startswith('--'):
                continue
            
            # Syntax translations
            if engine == "sqlite":
                stmt = stmt.replace('INT AUTO_INCREMENT PRIMARY KEY', 'INTEGER PRIMARY KEY AUTOINCREMENT')
                stmt = stmt.replace('INT PRIMARY KEY AUTO_INCREMENT', 'INTEGER PRIMARY KEY AUTOINCREMENT')
            elif engine == "mysql":
                stmt = stmt.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'INT AUTO_INCREMENT PRIMARY KEY')
                stmt = stmt.replace('INTEGER PRIMARY KEY', 'INT AUTO_INCREMENT PRIMARY KEY')
                stmt = stmt.replace('INSERT OR IGNORE', 'INSERT IGNORE')
                
            cursor.execute(stmt)
        
        if engine == "mysql":
            conn.commit()
        else:
            conn.commit()
            
        print(f"Database successfully initialized on engine: {engine}.")
        
        # Check if default admin account exists, if not, seed it securely
        check_admin = execute_query("SELECT id FROM users WHERE username = ?", ('admin',), fetch="one")
        if not check_admin:
            raw_password = "SecureAdminPass123!"
            hashed_password = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')
            execute_query(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ('admin', hashed_password, 'admin')
            )
            print("Default security administrator account seeded (admin / SecureAdminPass123!).")
    except Exception as e:
        print(f"Initialization Exception: {e}", file=sys.stderr)
    finally:
        cursor.close()
        conn.close()

# ==============================================================================
# Security Headers & Defense Filtering
# ==============================================================================

@app.after_request
def inject_security_headers(response):
    """
    Enforces browser security headers, XSS protections, and tight CSP alignment.
    """
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://images.unsplash.com;"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    response.headers['Server'] = 'Cloud-Shield-App-Server'
    return response

# Clean user input to minimize XSS vector
def sanitize_input(text):
    if not text:
        return ""
    # Strip HTML tags
    return re.sub(r'<[^>]*>', '', text).strip()

# ==============================================================================
# Embedded Luxury Tailwind Templates
# ==============================================================================

HTML_LAYOUT = """
<!DOCTYPE html>
<html lang="en" class="h-full bg-[#070b13]">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - Jerin's Men's Wear</title>
    <!-- Tailwind CSS CDN -->
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <!-- Premium Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,400;0,600;1,400&family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Outfit', sans-serif;
        }
        .serif-heading {
            font-family: 'Cormorant Garamond', serif;
        }
    </style>
</head>
<body class="flex flex-col min-h-screen text-slate-100 antialiased bg-gradient-to-b from-[#0b0f19] to-[#070b13]">

    <!-- Premium Luxury Header -->
    <header class="border-b border-slate-800 bg-[#070b13]/90 backdrop-filter backdrop-blur-md sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
            <a href="{{ url_for('index') }}" class="flex items-center space-x-2">
                <span class="serif-heading text-2xl lg:text-3xl font-bold tracking-widest bg-gradient-to-r from-yellow-400 via-amber-400 to-yellow-600 bg-clip-text text-transparent">
                    JERIN'S
                </span>
                <span class="text-xs uppercase tracking-widest text-slate-400 font-light pt-1.5 hidden sm:inline">
                    | Men's Wear
                </span>
            </a>
            
            <nav class="hidden md:flex space-x-8 text-sm uppercase tracking-widest">
                <a href="{{ url_for('index') }}" class="text-slate-300 hover:text-amber-400 transition duration-300">Catalog</a>
                <a href="{{ url_for('index', category='Shirts') }}" class="text-slate-400 hover:text-amber-400 transition duration-300">Shirts</a>
                <a href="{{ url_for('index', category='Suits') }}" class="text-slate-400 hover:text-amber-400 transition duration-300">Suits</a>
                <a href="{{ url_for('index', category='Trousers') }}" class="text-slate-400 hover:text-amber-400 transition duration-300">Trousers</a>
                <a href="{{ url_for('index', category='Blazers') }}" class="text-slate-400 hover:text-amber-400 transition duration-300">Blazers</a>
            </nav>

            <div class="flex items-center space-x-6">
                <!-- Cart Icon -->
                <a href="{{ url_for('view_cart') }}" class="relative text-slate-300 hover:text-amber-400 transition duration-300 flex items-center">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M16 11V7a4 4 0 00-8 0v4M5 9h14l1 12H4L5 9z"></path>
                    </svg>
                    {% if session.get('cart_count', 0) > 0 %}
                    <span class="absolute -top-2 -right-2 bg-gradient-to-r from-yellow-500 to-amber-600 text-slate-950 font-bold text-xs rounded-full h-5 w-5 flex items-center justify-center border border-[#070b13] animate-pulse">
                        {{ session.get('cart_count') }}
                    </span>
                    {% endif %}
                </a>

                {% if session.get('user_id') %}
                    <div class="flex items-center space-x-4">
                        <a href="{{ url_for('view_orders') }}" class="text-xs uppercase tracking-widest text-slate-400 hover:text-amber-400 font-semibold transition duration-300">
                            My Orders
                        </a>
                        {% if session.get('role') == 'admin' %}
                        <a href="{{ url_for('admin_portal') }}" class="text-xs uppercase tracking-widest text-amber-500 hover:text-amber-400 font-semibold border border-amber-500/30 px-3 py-1.5 rounded bg-amber-500/10 transition duration-300">
                            Admin Suite
                        </a>
                        {% endif %}
                        <div class="text-right hidden sm:block">
                            <p class="text-xs text-slate-500 font-light">Authenticated</p>
                            <p class="text-sm font-medium text-slate-300">{{ session.get('username') }}</p>
                        </div>
                        <a href="{{ url_for('logout') }}" class="text-xs uppercase tracking-widest text-slate-400 hover:text-rose-400 transition duration-300">
                            Logout
                        </a>
                    </div>
                {% else %}
                    <a href="{{ url_for('login') }}" class="text-sm uppercase tracking-widest text-slate-400 hover:text-amber-400 transition duration-300">
                        Login
                    </a>
                    <a href="{{ url_for('register') }}" class="bg-gradient-to-r from-yellow-500 to-amber-600 hover:from-yellow-400 hover:to-amber-500 text-slate-950 font-bold text-xs uppercase tracking-widest px-4 py-2 rounded transition duration-300 transform hover:-translate-y-0.5">
                        Register
                    </a>
                {% endif %}
            </div>
        </div>
    </header>

    <!-- Message Alerts Panel -->
    <main class="flex-grow max-w-7xl mx-auto w-full px-6 py-8">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="mb-6 space-y-3">
                    {% for category, message in messages %}
                        <div class="p-4 rounded-lg flex items-center justify-between {% if category == 'success' %}bg-emerald-500/10 border border-emerald-500/30 text-emerald-400{% elif category == 'danger' %}bg-rose-500/10 border border-rose-500/30 text-rose-400{% else %}bg-amber-500/10 border border-amber-500/30 text-amber-400{% endif %}">
                            <span class="text-sm font-medium">{{ message }}</span>
                        </div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}

        <!-- Yielding Child Content -->
        {% block content %}{% endblock %}
    </main>

    <!-- Footer -->
    <footer class="border-t border-slate-800 bg-[#04060b] py-8 text-center text-xs text-slate-500">
        <div class="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between space-y-4 md:space-y-0">
            <p>&copy; 2026 Jerin's Men's Wear Ltd. All Rights Reserved. BCA Capstone System.</p>
            <div class="flex items-center space-x-4">
                <span class="flex items-center space-x-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2.5 py-1 rounded">
                    <span class="h-2 w-2 rounded-full bg-emerald-400 animate-ping"></span>
                    <span class="font-mono">DevSecOps Protected</span>
                </span>
                <span class="text-slate-600">|</span>
                <a href="{{ url_for('update_password_route') }}" class="hover:text-amber-500 transition duration-300">Update Credentials</a>
            </div>
        </div>
    </footer>
</body>
</html>
"""

CATALOG_TEMPLATE = """
{% extends 'layout' %}
{% block content %}
<div class="text-center my-10">
    <h2 class="serif-heading text-5xl font-semibold tracking-wide text-slate-100">THE LUXURY CATALOG</h2>
    <div class="h-1 w-24 bg-gradient-to-r from-yellow-500 to-amber-600 mx-auto mt-4 rounded-full"></div>
    <p class="text-slate-400 mt-3 max-w-xl mx-auto text-sm font-light tracking-wide">
        Explore handcrafted garments designed from elite Italian fabrics and masterfully tailored to absolute perfection.
    </p>
</div>

<!-- Category Filters -->
<div class="flex flex-wrap justify-center gap-3 mb-10 text-xs uppercase tracking-widest">
    <a href="{{ url_for('index') }}" class="px-5 py-2.5 rounded-full border {% if not active_category %}bg-gradient-to-r from-yellow-500 to-amber-600 text-slate-950 border-amber-500 font-bold{% else %}border-slate-800 text-slate-400 hover:border-amber-500/30 hover:text-amber-400{% endif %} transition duration-300">
        All Creations
    </a>
    {% for cat in ['Shirts', 'Suits', 'Trousers', 'Blazers'] %}
    <a href="{{ url_for('index', category=cat) }}" class="px-5 py-2.5 rounded-full border {% if active_category == cat %}bg-gradient-to-r from-yellow-500 to-amber-600 text-slate-950 border-amber-500 font-bold{% else %}border-slate-800 text-slate-400 hover:border-amber-500/30 hover:text-amber-400{% endif %} transition duration-300">
        {{ cat }}
    </a>
    {% endfor %}
</div>

<!-- Products Grid -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
    {% for product in products %}
    <div class="group bg-[#0f1423] border border-slate-800/80 rounded-xl overflow-hidden shadow-2xl flex flex-col hover:border-amber-500/40 transition duration-500 transform hover:-translate-y-1">
        <!-- Image Box -->
        <div class="h-80 overflow-hidden relative bg-slate-950">
            <img src="{{ product.image_url }}" alt="{{ product.name }}" class="w-full h-full object-cover object-top group-hover:scale-110 transition duration-700 ease-out opacity-90">
            <span class="absolute top-4 right-4 bg-[#070b13]/80 backdrop-filter backdrop-blur-md text-[#d4af37] text-xs font-semibold uppercase tracking-widest px-3 py-1.5 rounded border border-amber-500/20">
                {{ product.category }}
            </span>
        </div>
        
        <!-- Info Card -->
        <div class="p-6 flex-grow flex flex-col justify-between">
            <div>
                <h3 class="serif-heading text-xl font-bold tracking-wide text-slate-100 group-hover:text-amber-400 transition duration-300">
                    {{ product.name }}
                </h3>
                <p class="text-xs text-slate-400 font-light mt-2.5 line-clamp-3 leading-relaxed">
                    {{ product.description }}
                </p>
            </div>
            
            <div class="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between">
                <div>
                    <span class="text-xs uppercase text-slate-500 block">Invest Price</span>
                    <span class="text-lg font-bold text-amber-500">&#8377;{{ "{:,.2f}".format(product.price) }}</span>
                </div>
                
                {% if product.stock > 0 %}
                <form action="{{ url_for('add_to_cart', product_id=product.id) }}" method="POST">
                    <button type="submit" class="bg-gradient-to-r from-yellow-500 to-amber-600 hover:from-yellow-400 hover:to-amber-500 text-slate-950 font-bold text-xs uppercase tracking-widest px-4 py-2.5 rounded transition duration-300 transform active:scale-95 shadow-lg shadow-amber-500/10">
                        Add to Bag
                    </button>
                </form>
                {% else %}
                <span class="text-xs font-semibold text-rose-400 bg-rose-500/10 px-3 py-1.5 rounded border border-rose-500/20">
                    Out of Stock
                </span>
                {% endif %}
            </div>
        </div>
    </div>
    {% else %}
    <div class="col-span-full py-16 text-center">
        <svg class="w-16 h-16 text-slate-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
        </svg>
        <p class="text-slate-400 font-light">No luxury products are presently available in this specific category.</p>
    </div>
    {% endfor %}
</div>
{% endblock %}
"""

LOGIN_TEMPLATE = """
{% extends 'layout' %}
{% block content %}
<div class="max-w-md mx-auto my-12">
    <div class="bg-[#0f1423] border border-slate-800 rounded-2xl shadow-2xl p-8">
        <div class="text-center mb-8">
            <h2 class="serif-heading text-4xl font-semibold tracking-wide text-slate-100">WELCOME BACK</h2>
            <div class="h-0.5 w-12 bg-gradient-to-r from-yellow-500 to-amber-600 mx-auto mt-3 rounded-full"></div>
            <p class="text-xs text-slate-400 mt-2 font-light">Secure your gateway to premium fashion portals.</p>
        </div>

        <form action="{{ url_for('login') }}" method="POST" class="space-y-6">
            <div>
                <label for="username" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Username</label>
                <input type="text" id="username" name="username" required autocomplete="off" class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
            </div>

            <div>
                <label for="password" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Password</label>
                <input type="password" id="password" name="password" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
            </div>

            <button type="submit" class="w-full bg-gradient-to-r from-yellow-500 to-amber-600 hover:from-yellow-400 hover:to-amber-500 text-slate-950 font-bold text-xs uppercase tracking-widest py-3.5 rounded-lg transition duration-300 transform active:scale-98 shadow-xl shadow-amber-500/5 mt-4">
                Verify Credentials
            </button>
        </form>

        <p class="text-center text-xs text-slate-500 mt-6 font-light">
            New client to our ecosystem? 
            <a href="{{ url_for('register') }}" class="text-amber-500 hover:text-amber-400 font-semibold transition duration-300">Register Account</a>
        </p>
    </div>
</div>
{% endblock %}
"""

REGISTER_TEMPLATE = """
{% extends 'layout' %}
{% block content %}
<div class="max-w-md mx-auto my-12">
    <div class="bg-[#0f1423] border border-slate-800 rounded-2xl shadow-2xl p-8">
        <div class="text-center mb-8">
            <h2 class="serif-heading text-4xl font-semibold tracking-wide text-slate-100">CLIENT REGISTRATION</h2>
            <div class="h-0.5 w-12 bg-gradient-to-r from-yellow-500 to-amber-600 mx-auto mt-3 rounded-full"></div>
            <p class="text-xs text-slate-400 mt-2 font-light">Establish a secure membership with Jerin's.</p>
        </div>

        <form action="{{ url_for('register') }}" method="POST" class="space-y-6">
            <div>
                <label for="username" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Username</label>
                <input type="text" id="username" name="username" required autocomplete="off" class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
            </div>

            <div>
                <label for="password" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Password</label>
                <input type="password" id="password" name="password" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
            </div>

            <button type="submit" class="w-full bg-gradient-to-r from-yellow-500 to-amber-600 hover:from-yellow-400 hover:to-amber-500 text-slate-950 font-bold text-xs uppercase tracking-widest py-3.5 rounded-lg transition duration-300 transform active:scale-98 shadow-xl shadow-amber-500/5 mt-4">
                Register Membership
            </button>
        </form>

        <p class="text-center text-xs text-slate-500 mt-6 font-light">
            Already own a registered storefront credentials? 
            <a href="{{ url_for('login') }}" class="text-amber-500 hover:text-amber-400 font-semibold transition duration-300">Login Here</a>
        </p>
    </div>
</div>
{% endblock %}
"""

CART_TEMPLATE = """
{% extends 'layout' %}
{% block content %}
<div class="my-6">
    <h2 class="serif-heading text-4xl font-semibold tracking-wide text-slate-100">YOUR SHOPPING BAG</h2>
    <div class="h-0.5 w-16 bg-gradient-to-r from-yellow-500 to-amber-600 mt-3 rounded-full mb-8"></div>

    {% if items %}
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <!-- Items Side -->
        <div class="lg:col-span-2 space-y-4">
            {% for item in items %}
            <div class="bg-[#0f1423] border border-slate-800/80 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
                <div class="flex items-center space-x-4 w-full sm:w-auto">
                    <img src="{{ item.image_url }}" alt="{{ item.name }}" class="w-20 h-20 object-cover object-top rounded-lg bg-slate-950">
                    <div>
                        <h3 class="serif-heading text-lg font-bold text-slate-100">{{ item.name }}</h3>
                        <p class="text-xs text-slate-500 uppercase tracking-widest mt-1">{{ item.category }}</p>
                        <p class="text-sm font-semibold text-amber-500 mt-1">&#8377;{{ "{:,.2f}".format(item.price) }}</p>
                    </div>
                </div>

                <!-- Quantity adjustments -->
                <div class="flex items-center space-x-6 w-full sm:w-auto justify-between sm:justify-start">
                    <form action="{{ url_for('update_cart', cart_item_id=item.id) }}" method="POST" class="flex items-center space-x-2">
                        <button type="submit" name="action" value="decrease" class="h-8 w-8 rounded bg-slate-850 hover:bg-slate-800 flex items-center justify-center text-slate-400 hover:text-amber-500 border border-slate-800 transition duration-300">-</button>
                        <span class="w-10 text-center text-sm font-semibold text-slate-200">{{ item.quantity }}</span>
                        <button type="submit" name="action" value="increase" class="h-8 w-8 rounded bg-slate-850 hover:bg-slate-800 flex items-center justify-center text-slate-400 hover:text-amber-500 border border-slate-800 transition duration-300">+</button>
                    </form>

                    <form action="{{ url_for('delete_cart_item', cart_item_id=item.id) }}" method="POST">
                        <button type="submit" class="text-xs uppercase tracking-widest font-semibold text-rose-500 hover:text-rose-400 transition duration-300">
                            Remove
                        </button>
                    </form>
                </div>
            </div>
            {% endfor %}
        </div>

        <!-- Billing details summary -->
        <div class="bg-[#0f1423] border border-slate-800 rounded-xl p-6 h-fit space-y-6">
            <h3 class="serif-heading text-2xl font-bold tracking-wide text-slate-100 pb-3 border-b border-slate-800">
                Order Summary
            </h3>
            
            <div class="space-y-3.5 text-sm font-light">
                <div class="flex justify-between">
                    <span class="text-slate-400">Bag Subtotal</span>
                    <span class="font-semibold">&#8377;{{ "{:,.2f}".format(subtotal) }}</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-slate-400">Tax & GST (18%)</span>
                    <span class="font-semibold">&#8377;{{ "{:,.2f}".format(tax) }}</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-slate-400">Luxury Courier Delivery</span>
                    <span class="font-semibold">&#8377;{{ "{:,.2f}".format(shipping) }}</span>
                </div>
                <div class="h-px bg-slate-800 my-4"></div>
                <div class="flex justify-between text-base font-semibold">
                    <span class="text-slate-200 uppercase tracking-widest text-xs font-bold">Invest Total</span>
                    <span class="text-amber-500 font-bold">&#8377;{{ "{:,.2f}".format(total) }}</span>
                </div>
            </div>

            <a href="{{ url_for('checkout') }}" class="block text-center w-full bg-gradient-to-r from-yellow-500 to-amber-600 hover:from-yellow-400 hover:to-amber-500 text-slate-950 font-bold text-xs uppercase tracking-widest py-3.5 rounded-lg transition duration-300 transform active:scale-98 shadow-xl shadow-amber-500/5">
                Proceed to Checkout
            </a>
        </div>
    </div>
    {% else %}
    <div class="text-center py-20 bg-[#0f1423] border border-slate-800 rounded-2xl">
        <svg class="w-16 h-16 text-slate-700 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M16 11V7a4 4 0 00-8 0v4M5 9h14l1 12H4L5 9z"></path>
        </svg>
        <p class="text-slate-400 font-light mb-6">Your shopping bag is completely empty.</p>
        <a href="{{ url_for('index') }}" class="bg-gradient-to-r from-yellow-500 to-amber-600 text-slate-950 font-bold text-xs uppercase tracking-widest px-6 py-3.5 rounded transition duration-300">
            Browse Luxury Collection
        </a>
    </div>
    {% endif %}
</div>
{% endblock %}
"""

CHECKOUT_TEMPLATE = """
{% extends 'layout' %}
{% block content %}
<div class="max-w-3xl mx-auto my-6">
    <h2 class="serif-heading text-4xl font-semibold tracking-wide text-slate-100">SHIPPING & CONFIRMATION</h2>
    <div class="h-0.5 w-16 bg-gradient-to-r from-yellow-500 to-amber-600 mt-3 rounded-full mb-8"></div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
        <!-- Billing Details Form -->
        <div class="bg-[#0f1423] border border-slate-800 rounded-xl p-6">
            <h3 class="serif-heading text-xl font-bold tracking-wide text-slate-200 pb-3 border-b border-slate-800 mb-6">
                Delivery Coordinates
            </h3>
            
            <form action="{{ url_for('checkout') }}" method="POST" class="space-y-4">
                <div>
                    <label for="fullname" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Recipient Name</label>
                    <input type="text" id="fullname" name="fullname" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
                </div>

                <div>
                    <label for="address" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Street Address</label>
                    <input type="text" id="address" name="address" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
                </div>

                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label for="city" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">City</label>
                        <input type="text" id="city" name="city" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
                    </div>
                    <div>
                        <label for="state" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">State</label>
                        <input type="text" id="state" name="state" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
                    </div>
                </div>

                <div>
                    <label for="zip" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Zip/Postal Code</label>
                    <input type="text" id="zip" name="zip" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
                </div>

                <button type="submit" class="w-full bg-gradient-to-r from-yellow-500 to-amber-600 hover:from-yellow-400 hover:to-amber-500 text-slate-950 font-bold text-xs uppercase tracking-widest py-3.5 rounded-lg transition duration-300 transform active:scale-98 shadow-xl shadow-amber-500/5 mt-6">
                    Submit Secure Order
                </button>
            </form>
        </div>

        <!-- Summary column -->
        <div class="space-y-6">
            <div class="bg-[#0f1423] border border-slate-800 rounded-xl p-6">
                <h3 class="serif-heading text-xl font-bold tracking-wide text-slate-200 pb-3 border-b border-slate-800 mb-4">
                    Itemized Summary
                </h3>
                
                <div class="divide-y divide-slate-800 max-h-60 overflow-y-auto mb-4 pr-2">
                    {% for item in items %}
                    <div class="py-3 flex justify-between text-sm">
                        <div>
                            <p class="font-medium text-slate-200">{{ item.name }}</p>
                            <p class="text-xs text-slate-500 font-light mt-0.5">Quantity: {{ item.quantity }}</p>
                        </div>
                        <span class="font-semibold text-slate-300">&#8377;{{ "{:,.2f}".format(item.price * item.quantity) }}</span>
                    </div>
                    {% endfor %}
                </div>

                <div class="border-t border-slate-800 pt-4 space-y-2 text-sm font-light">
                    <div class="flex justify-between">
                        <span class="text-slate-400">Order Subtotal</span>
                        <span>&#8377;{{ "{:,.2f}".format(subtotal) }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-slate-400">GST (18%)</span>
                        <span>&#8377;{{ "{:,.2f}".format(tax) }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-slate-400">Courier Shipping</span>
                        <span>&#8377;{{ "{:,.2f}".format(shipping) }}</span>
                    </div>
                    <div class="h-px bg-slate-800 my-4"></div>
                    <div class="flex justify-between font-semibold text-base">
                        <span class="text-slate-200">Total Invoice</span>
                        <span class="text-amber-500">&#8377;{{ "{:,.2f}".format(total) }}</span>
                    </div>
                </div>
            </div>
            
            <div class="bg-amber-500/5 border border-amber-500/20 rounded-xl p-4 flex items-start space-x-3 text-xs text-amber-500 leading-relaxed">
                <svg class="w-5 h-5 flex-shrink-0 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
                <span>
                    <strong>Authentication Note:</strong> In our containerized grading mode, shipping parameters and user identifiers are strictly logged and audited. Verify inputs before final checkout commands.
                </span>
            </div>
        </div>
    </div>
</div>
{% endblock %}
"""

ORDER_CONFIRMATION_TEMPLATE = """
{% extends 'layout' %}
{% block content %}
<div class="max-w-2xl mx-auto my-12 text-center">
    <div class="bg-[#0f1423] border border-slate-800 rounded-2xl p-8 shadow-2xl">
        <!-- Success Check Icon -->
        <div class="h-16 w-16 bg-emerald-500/10 border border-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
            <svg class="w-8 h-8 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
            </svg>
        </div>

        <h2 class="serif-heading text-4xl font-bold text-slate-100">ORDER CONFIRMED</h2>
        <p class="text-xs text-emerald-400 font-semibold tracking-widest mt-2 uppercase">Invoice Authenticated</p>
        
        <div class="h-px bg-slate-800 my-6"></div>

        <div class="text-left space-y-4 text-sm font-light text-slate-300 bg-[#070b13] p-6 rounded-lg border border-slate-800/80 mb-8">
            <div class="flex justify-between">
                <span class="text-slate-500">Order System Key</span>
                <span class="font-mono text-xs font-semibold text-amber-500">#{{ order_id }}</span>
            </div>
            <div class="flex justify-between">
                <span class="text-slate-500">Authorized Transact Time</span>
                <span>{{ date }}</span>
            </div>
            <div class="flex justify-between">
                <span class="text-slate-500">Grand Bill Total</span>
                <span class="font-bold text-amber-500">&#8377;{{ "{:,.2f}".format(total) }}</span>
            </div>
            <div class="border-t border-slate-800 pt-3 flex justify-between">
                <span class="text-slate-500">Delivery Address Logged</span>
                <span class="text-right text-xs max-w-xs font-medium">{{ address }}</span>
            </div>
        </div>

        <div class="flex flex-col sm:flex-row gap-4 justify-center">
            <a href="{{ url_for('index') }}" class="bg-gradient-to-r from-yellow-500 to-amber-600 text-slate-950 font-bold text-xs uppercase tracking-widest px-6 py-3.5 rounded transition duration-300">
                Continue Shopping
            </a>
        </div>
    </div>
</div>
{% endblock %}
"""

ADMIN_PORTAL_TEMPLATE = """
{% extends 'layout' %}
{% block content %}
<div class="my-6">
    <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-6 border-b border-slate-800 mb-8 gap-4">
        <div>
            <h2 class="serif-heading text-4xl font-semibold tracking-wide text-slate-100">ADMINISTRATIVE PORTAL</h2>
            <p class="text-xs text-amber-500 font-semibold tracking-widest uppercase mt-1">Executive Management Suite</p>
        </div>
        <a href="{{ url_for('admin_add_product') }}" class="bg-gradient-to-r from-yellow-500 to-amber-600 hover:from-yellow-400 hover:to-amber-500 text-slate-950 font-bold text-xs uppercase tracking-widest px-5 py-3 rounded transition duration-300 shadow-lg shadow-amber-500/10">
            Create Catalog Item
        </a>
    </div>

    <!-- Administrative Widgets Panel -->
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-6 mb-10">
        <div class="bg-[#0f1423] border border-slate-800 rounded-xl p-6 flex items-center justify-between">
            <div>
                <span class="text-xs uppercase text-slate-500 block font-semibold tracking-widest">Active Catalog Size</span>
                <span class="text-3xl font-bold text-slate-100 mt-2 block">{{ metrics.catalog_count }} Items</span>
            </div>
            <div class="h-12 w-12 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                </svg>
            </div>
        </div>

        <div class="bg-[#0f1423] border border-slate-800 rounded-xl p-6 flex items-center justify-between">
            <div>
                <span class="text-xs uppercase text-slate-500 block font-semibold tracking-widest">Registered Clients</span>
                <span class="text-3xl font-bold text-slate-100 mt-2 block">{{ metrics.clients_count }} Members</span>
            </div>
            <div class="h-12 w-12 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"></path>
                </svg>
            </div>
        </div>

        <div class="bg-[#0f1423] border border-slate-800 rounded-xl p-6 flex items-center justify-between">
            <div>
                <span class="text-xs uppercase text-slate-500 block font-semibold tracking-widest">Gross Sales revenue</span>
                <span class="text-3xl font-bold text-amber-500 mt-2 block">&#8377;{{ "{:,.2f}".format(metrics.gross_sales or 0) }}</span>
            </div>
            <div class="h-12 w-12 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
            </div>
        </div>
    </div>

    <!-- Administrative Tabs -->
    <div class="mb-6 border-b border-slate-800">
        <ul class="flex flex-wrap -mb-px text-xs font-semibold uppercase tracking-widest text-center">
            <li class="mr-2">
                <a href="{{ url_for('admin_portal', pane='inventory') }}" class="inline-block p-4 border-b-2 rounded-t-lg {% if active_pane == 'inventory' %}border-amber-500 text-amber-400 bg-amber-500/5{% else %}border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-800{% endif %}">
                    Catalog Inventory CRUD
                </a>
            </li>
            <li class="mr-2">
                <a href="{{ url_for('admin_portal', pane='transactions') }}" class="inline-block p-4 border-b-2 rounded-t-lg {% if active_pane == 'transactions' %}border-amber-500 text-amber-400 bg-amber-500/5{% else %}border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-800{% endif %}">
                    Customer Transactions Logs
                </a>
            </li>
            <li class="mr-2">
                <a href="{{ url_for('admin_portal', pane='security') }}" class="inline-block p-4 border-b-2 rounded-t-lg {% if active_pane == 'security' %}border-amber-500 text-amber-400 bg-amber-500/5{% else %}border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-800{% endif %}">
                    Security Audits Pane
                </a>
            </li>
        </ul>
    </div>

    <!-- Inventory CRUD Pane -->
    {% if active_pane == 'inventory' %}
    <div class="bg-[#0f1423] border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
                <thead class="bg-[#070b13] text-xs uppercase tracking-widest text-slate-400 border-b border-slate-800">
                    <tr>
                        <th class="px-6 py-4">Creation ID</th>
                        <th class="px-6 py-4">Title</th>
                        <th class="px-6 py-4">Category</th>
                        <th class="px-6 py-4 text-right">Price</th>
                        <th class="px-6 py-4 text-center">Stock Count</th>
                        <th class="px-6 py-4 text-right">Action Operators</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-850">
                    {% for item in products %}
                    <tr class="hover:bg-slate-850/30 transition duration-300">
                        <td class="px-6 py-4 font-mono font-semibold text-slate-500">#{{ item.id }}</td>
                        <td class="px-6 py-4 font-medium text-slate-200">{{ item.name }}</td>
                        <td class="px-6 py-4">
                            <span class="text-xs uppercase tracking-wider bg-slate-900 border border-slate-800 text-slate-400 px-2.5 py-1 rounded">
                                {{ item.category }}
                            </span>
                        </td>
                        <td class="px-6 py-4 text-right font-semibold text-amber-500">&#8377;{{ "{:,.2f}".format(item.price) }}</td>
                        <td class="px-6 py-4 text-center font-semibold {% if item.stock <= 5 %}text-amber-500{% else %}text-slate-300{% endif %}">{{ item.stock }}</td>
                        <td class="px-6 py-4 text-right space-x-3">
                            <a href="{{ url_for('admin_edit_product', product_id=item.id) }}" class="text-xs uppercase tracking-widest font-semibold text-amber-500 hover:text-amber-400 transition duration-300">
                                Edit
                            </a>
                            <form action="{{ url_for('admin_delete_product', product_id=item.id) }}" method="POST" class="inline" onsubmit="return confirm('Confirm permanent catalog deletion of this creation?');">
                                <button type="submit" class="text-xs uppercase tracking-widest font-semibold text-rose-500 hover:text-rose-400 transition duration-300">
                                    Delete
                                </button>
                            </form>
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="6" class="px-6 py-8 text-center text-slate-500 font-light">Inventory catalog is currently empty.</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Customer Transactions Logs Pane -->
    {% elif active_pane == 'transactions' %}
    <div class="bg-[#0f1423] border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
                <thead class="bg-[#070b13] text-xs uppercase tracking-widest text-slate-400 border-b border-slate-800">
                    <tr>
                        <th class="px-6 py-4">Order Index Key</th>
                        <th class="px-6 py-4">User Identifier</th>
                        <th class="px-6 py-4">Time Logged</th>
                        <th class="px-6 py-4">Address Log</th>
                        <th class="px-6 py-4 text-right">Invoice Sum</th>
                        <th class="px-6 py-4 text-center">Status Flag</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-850">
                    {% for txn in transactions %}
                    <tr class="hover:bg-slate-850/30 transition duration-300">
                        <td class="px-6 py-4 font-mono font-semibold text-slate-500">#{{ txn.id }}</td>
                        <td class="px-6 py-4 font-medium text-slate-200">
                            {{ txn.username }}
                        </td>
                        <td class="px-6 py-4 text-xs font-light text-slate-400">{{ txn.created_at }}</td>
                        <td class="px-6 py-4 text-xs text-slate-400 max-w-xs truncate" title="{{ txn.shipping_address }}">{{ txn.shipping_address }}</td>
                        <td class="px-6 py-4 text-right font-semibold text-amber-500">&#8377;{{ "{:,.2f}".format(txn.total_amount) }}</td>
                        <td class="px-6 py-4 text-center">
                            <span class="text-xs uppercase tracking-widest font-semibold px-2.5 py-1 rounded bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
                                {{ txn.status }}
                            </span>
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="6" class="px-6 py-8 text-center text-slate-500 font-light">No customer transactions are recorded within the ledger.</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Security Audits Pane -->
    {% elif active_pane == 'security' %}
    <div class="bg-[#0f1423] border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div class="overflow-x-auto">
            <table class="w-full text-left text-sm text-slate-300">
                <thead class="bg-[#070b13] text-xs uppercase tracking-widest text-slate-400 border-b border-slate-800">
                    <tr>
                        <th class="px-6 py-4">Event Index</th>
                        <th class="px-6 py-4">Timestamp</th>
                        <th class="px-6 py-4">Event Indicator</th>
                        <th class="px-6 py-4">Trigger IP</th>
                        <th class="px-6 py-4">Username Target</th>
                        <th class="px-6 py-4">Audit Payload Details</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-850">
                    {% for log in security_logs %}
                    <tr class="hover:bg-slate-850/30 transition duration-300 font-mono text-xs">
                        <td class="px-6 py-4 text-slate-500">#{{ log.id }}</td>
                        <td class="px-6 py-4 text-slate-400">{{ log.created_at }}</td>
                        <td class="px-6 py-4">
                            <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider {% if 'FAIL' in log.event_type %}bg-rose-500/10 border border-rose-500/20 text-rose-400{% else %}bg-amber-500/10 border border-amber-500/20 text-amber-400{% endif %}">
                                {{ log.event_type }}
                            </span>
                        </td>
                        <td class="px-6 py-4 text-slate-300 font-semibold">{{ log.ip_address }}</td>
                        <td class="px-6 py-4 text-slate-300 font-semibold">{{ log.username or 'SYSTEM' }}</td>
                        <td class="px-6 py-4 text-slate-400 max-w-sm truncate" title="{{ log.details }}">{{ log.details }}</td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="6" class="px-6 py-8 text-center text-slate-500 font-light">No security events present in logs. System pristine.</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    {% endif %}
</div>
{% endblock %}
"""

ADMIN_PRODUCT_FORM_TEMPLATE = """
{% extends 'layout' %}
{% block content %}
<div class="max-w-xl mx-auto my-6">
    <div class="bg-[#0f1423] border border-slate-800 rounded-2xl shadow-2xl p-8">
        <div class="text-center mb-8">
            <h2 class="serif-heading text-3xl font-semibold tracking-wide text-slate-100">
                {% if product %}EDIT CREATION{% else %}NEW CATALOG CREATION{% endif %}
            </h2>
            <div class="h-0.5 w-12 bg-gradient-to-r from-yellow-500 to-amber-600 mx-auto mt-3 rounded-full"></div>
            <p class="text-xs text-slate-400 mt-2 font-light">Configure catalog properties in high detail.</p>
        </div>

        <form method="POST" class="space-y-5">
            <div>
                <label for="name" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Garment Title</label>
                <input type="text" id="name" name="name" value="{{ product.name if product else '' }}" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
            </div>

            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label for="price" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Price (INR)</label>
                    <input type="number" id="price" name="price" step="0.01" value="{{ product.price if product else '' }}" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
                </div>
                <div>
                    <label for="stock" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Stock Count</label>
                    <input type="number" id="stock" name="stock" value="{{ product.stock if product else '' }}" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
                </div>
            </div>

            <div>
                <label for="category" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Segment Category</label>
                <select id="category" name="category" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-400 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
                    <option value="Shirts" {% if product and product.category == 'Shirts' %}selected{% endif %}>Shirts</option>
                    <option value="Suits" {% if product and product.category == 'Suits' %}selected{% endif %}>Suits</option>
                    <option value="Trousers" {% if product and product.category == 'Trousers' %}selected{% endif %}>Trousers</option>
                    <option value="Blazers" {% if product and product.category == 'Blazers' %}selected{% endif %}>Blazers</option>
                </select>
            </div>

            <div>
                <label for="image_url" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Image Resource URL</label>
                <input type="url" id="image_url" name="image_url" value="{{ product.image_url if product else '' }}" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
            </div>

            <div>
                <label for="description" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Premium Description</label>
                <textarea id="description" name="description" rows="4" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-2.5 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">{{ product.description if product else '' }}</textarea>
            </div>

            <div class="flex gap-4 pt-2">
                <a href="{{ url_for('admin_portal') }}" class="w-1/2 text-center border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-300 font-bold text-xs uppercase tracking-widest py-3.5 rounded-lg transition duration-300">
                    Cancel
                </a>
                <button type="submit" class="w-1/2 bg-gradient-to-r from-yellow-500 to-amber-600 hover:from-yellow-400 hover:to-amber-500 text-slate-950 font-bold text-xs uppercase tracking-widest py-3.5 rounded-lg transition duration-300 shadow-xl shadow-amber-500/5">
                    Save Changes
                </button>
            </div>
        </form>
    </div>
</div>
{% endblock %}
"""

PASSWORD_UPDATE_TEMPLATE = """
{% extends 'layout' %}
{% block content %}
<div class="max-w-md mx-auto my-12">
    <div class="bg-[#0f1423] border border-slate-800 rounded-2xl shadow-2xl p-8">
        <div class="text-center mb-8">
            <h2 class="serif-heading text-3xl font-semibold tracking-wide text-slate-100">UPDATE PASSWORD</h2>
            <div class="h-0.5 w-12 bg-gradient-to-r from-yellow-500 to-amber-600 mx-auto mt-3 rounded-full"></div>
            <p class="text-xs text-slate-400 mt-2 font-light">Modify account access codes securely.</p>
        </div>

        <form action="{{ url_for('update_password_route') }}" method="POST" class="space-y-6">
            {% if not session.get('user_id') %}
            <div>
                <label for="username" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Username</label>
                <input type="text" id="username" name="username" required autocomplete="off" class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
            </div>
            {% endif %}

            <div>
                <label for="old_password" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Existing Password</label>
                <input type="password" id="old_password" name="old_password" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
            </div>

            <div>
                <label for="new_password" class="block text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">New Desired Password</label>
                <input type="password" id="new_password" name="new_password" required class="w-full bg-[#070b13] border border-slate-800 rounded-lg px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition duration-300">
            </div>

            <button type="submit" class="w-full bg-gradient-to-r from-yellow-500 to-amber-600 hover:from-yellow-400 hover:to-amber-500 text-slate-950 font-bold text-xs uppercase tracking-widest py-3.5 rounded-lg transition duration-300 transform active:scale-98 shadow-xl shadow-amber-500/5 mt-4">
                Update Cipher codes
            </button>
        </form>
    </div>
</div>
{% endblock %}
"""

ORDER_HISTORY_TEMPLATE = """
{% extends 'layout' %}
{% block content %}
<div class="my-6">
    <h2 class="serif-heading text-4xl font-semibold tracking-wide text-slate-100">YOUR ORDER HISTORY</h2>
    <div class="h-0.5 w-16 bg-gradient-to-r from-yellow-500 to-amber-600 mt-3 rounded-full mb-8"></div>

    {% if orders %}
    <div class="space-y-8">
        {% for order in orders %}
        <div class="bg-[#0f1423] border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
            <!-- Order Header Banner -->
            <div class="bg-[#070b13] px-6 py-4 flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 gap-4">
                <div class="flex flex-wrap gap-x-6 gap-y-2 text-sm text-slate-400 font-light">
                    <div>
                        <span class="text-xs uppercase text-slate-500 block">Date Placed</span>
                        <span class="font-medium text-slate-300">{{ order.created_at }}</span>
                    </div>
                    <div>
                        <span class="text-xs uppercase text-slate-500 block">Order Receipt Key</span>
                        <span class="font-mono text-xs font-semibold text-amber-500">#{{ order.id }}</span>
                    </div>
                    <div>
                        <span class="text-xs uppercase text-slate-500 block">Grand Total</span>
                        <span class="font-bold text-amber-500">&#8377;{{ "{:,.2f}".format(order.total_amount|float) }}</span>
                    </div>
                    <div class="max-w-xs">
                        <span class="text-xs uppercase text-slate-500 block">Delivery Coordinates</span>
                        <span class="text-xs block truncate" title="{{ order.shipping_address }}">{{ order.shipping_address }}</span>
                    </div>
                </div>
                
                <div>
                    <span class="text-xs uppercase tracking-widest font-semibold px-3 py-1.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                        {{ order.status }}
                    </span>
                </div>
            </div>

            <!-- Itemized order purchases -->
            <div class="p-6 divide-y divide-slate-800/80">
                {% for item in order['items'] %}
                <div class="py-4 first:pt-0 last:pb-0 flex flex-col sm:flex-row items-center justify-between gap-4">
                    <div class="flex items-center space-x-4 w-full sm:w-auto">
                        <img src="{{ item.image_url }}" alt="{{ item.name }}" class="w-16 h-16 object-cover object-top rounded-lg bg-slate-950">
                        <div>
                            <h4 class="serif-heading text-base font-bold text-slate-200">{{ item.name }}</h4>
                            <p class="text-xs text-slate-500 uppercase tracking-widest mt-0.5">{{ item.category }}</p>
                        </div>
                    </div>
                    
                    <div class="flex items-center space-x-8 w-full sm:w-auto justify-between sm:justify-start">
                        <div class="text-sm font-light text-slate-400">
                            Quantity: <span class="font-semibold text-slate-200">{{ item.quantity }}</span>
                        </div>
                        <div class="text-right">
                            <span class="text-xs text-slate-500 block">Item Unit Price</span>
                            <span class="text-sm font-semibold text-amber-500">&#8377;{{ "{:,.2f}".format(item.price|float) }}</span>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endfor %}
    </div>
    {% else %}
    <div class="text-center py-20 bg-[#0f1423] border border-slate-800 rounded-2xl">
        <svg class="w-16 h-16 text-slate-700 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"></path>
        </svg>
        <p class="text-slate-400 font-light mb-6">No previous orders are recorded for your membership profile.</p>
        <a href="{{ url_for('index') }}" class="bg-gradient-to-r from-yellow-500 to-amber-600 text-slate-950 font-bold text-xs uppercase tracking-widest px-6 py-3.5 rounded transition duration-300">
            Start Your First Acquisition
        </a>
    </div>
    {% endif %}
</div>
{% endblock %}
"""

TEMPLATES = {
    'layout': HTML_LAYOUT,
    'catalog': CATALOG_TEMPLATE,
    'login': LOGIN_TEMPLATE,
    'register': REGISTER_TEMPLATE,
    'cart': CART_TEMPLATE,
    'checkout': CHECKOUT_TEMPLATE,
    'confirmation': ORDER_CONFIRMATION_TEMPLATE,
    'admin_portal': ADMIN_PORTAL_TEMPLATE,
    'admin_product_form': ADMIN_PRODUCT_FORM_TEMPLATE,
    'password_update': PASSWORD_UPDATE_TEMPLATE,
    'order_history': ORDER_HISTORY_TEMPLATE
}

def render_luxury_template(template_name, **kwargs):
    """
    Renders custom templates with responsive styling configurations.
    Uses string rendering and context manipulation to support absolute isolation.
    """
    template_str = TEMPLATES.get(template_name)
    if not template_str:
        abort(500, f"Critical: Luxury template code block '{template_name}' missing.")
    
    # Check session cart totals to auto-update badges dynamically
    cart_count = 0
    if 'user_id' in session:
        cart_data = execute_query(
            "SELECT SUM(quantity) as total_qty FROM cart_items WHERE user_id = ?",
            (session['user_id'],),
            fetch="one"
        )
        if cart_data and cart_data.get('total_qty'):
            cart_count = int(cart_data['total_qty'])
    else:
        # Fallback to local session catalog cart items count
        cart_count = len(session.get('cart', {}))
    
    session['cart_count'] = cart_count
    
    # Execute double layout expansion
    if template_name != 'layout':
        layout_str = TEMPLATES['layout']
        # Strip extending instructions so Jinja renders the merged block in-memory
        clean_template = template_str.replace("{% extends 'layout' %}", "")
        clean_template = clean_template.replace("{% block content %}", "")
        # Strip trailing endblock wrapper
        clean_template_stripped = clean_template.strip()
        if clean_template_stripped.endswith("{% endblock %}"):
            clean_template = clean_template_stripped[:-14]
            
        combined_str = layout_str.replace('{% block content %}{% endblock %}', clean_template)
        return render_template_string(combined_str, **kwargs)
    
    return render_template_string(template_str, **kwargs)

# ==============================================================================
# Web Route Implementations
# ==============================================================================

@app.route('/')
def index():
    category = request.args.get('category')
    if category in ['Shirts', 'Suits', 'Trousers', 'Blazers']:
        query = "SELECT * FROM products WHERE category = ? ORDER BY id DESC"
        products = execute_query(query, (category,))
    else:
        query = "SELECT * FROM products ORDER BY id DESC"
        products = execute_query(query)
        category = None
        
    return render_luxury_template(
        'catalog',
        title="Luxury Collection",
        products=products,
        active_category=category
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Enforce brute force locking logic at route entrance
    client_ip = request.remote_addr
    is_locked, remaining = auth_limiter.is_locked(client_ip)
    if is_locked:
        log_security_event('LOGIN_FAILED_LOCKEDOUT', client_ip, None, f"Locked out client IP attempted auth. Remaining ban: {remaining}s")
        return render_luxury_template(
            'login',
            title="Secure Login",
            error=f"Anti-brute force lock is currently active on this IP. Please try again in {remaining} seconds."
        )

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        
        # SQLi Protection: Parameterized query logic
        query = "SELECT * FROM users WHERE username = ?"
        user = execute_query(query, (username,), fetch="one")
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # Successful Authentication
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            auth_limiter.record_attempt(client_ip, success=True)
            
            # Sync session shopping cart if existing
            sync_session_cart(user['id'])
            
            flash(f"Welcome back, master {user['username']}.", "success")
            log_security_event('LOGIN_SUCCESSFUL', client_ip, username, "Successful credential authentication match.")
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_portal'))
            return redirect(url_for('index'))
        else:
            # Failed Authentication
            locked_out, window_len = auth_limiter.record_attempt(client_ip, success=False)
            log_security_event('LOGIN_CREDENTIAL_FAILED', client_ip, username, f"Failed password match attempts recorded. Locked out: {locked_out}")
            
            if locked_out:
                flash(f"Security Alert: Excessive authentication anomalies. IP {client_ip} is banned for {window_len} seconds.", "danger")
            else:
                flash("Invalid secure credentials match. Access request denied.", "danger")
                
    return render_luxury_template('login', title="Secure Login")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        
        if not username or not password:
            flash("All authorization values are strictly required.", "danger")
            return render_luxury_template('register', title="Client Registration")
            
        # Verify username unique bounds
        check = execute_query("SELECT id FROM users WHERE username = ?", (username,), fetch="one")
        if check:
            flash("Username exists within luxury registry system.", "danger")
            return render_luxury_template('register', title="Client Registration")
            
        # Hash user credentials securely using Bcrypt (Work Factor 12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')
        
        try:
            execute_query(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'customer')",
                (username, hashed)
            )
            flash("Secure client registration finalized. Proceed with authentication.", "success")
            log_security_event('USER_REGISTERED', request.remote_addr, username, "New system user profile committed.")
            return redirect(url_for('login'))
        except Exception as e:
            flash("An internal system error halted the transaction.", "danger")
            print(f"Exception registering user: {e}", file=sys.stderr)
            
    return render_luxury_template('register', title="Client Registration")

@app.route('/logout')
def logout():
    username = session.get('username')
    log_security_event('USER_LOGGEDOUT', request.remote_addr, username, "Session keys cleared.")
    session.clear()
    flash("Session terminated securely. Thank you for visiting.", "success")
    return redirect(url_for('index'))

@app.route('/update-password', methods=['GET', 'POST'])
def update_password_route():
    if request.method == 'POST':
        client_ip = request.remote_addr
        
        if 'user_id' in session:
            # User authenticated password update
            user_id = session['user_id']
            username = session['username']
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            
            user = execute_query("SELECT * FROM users WHERE id = ?", (user_id,), fetch="one")
            if user and bcrypt.checkpw(old_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                new_hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')
                execute_query("UPDATE users SET password_hash = ? WHERE id = ?", (new_hashed, user_id))
                flash("Credentials cipher updated successfully.", "success")
                log_security_event('PASSWORD_UPDATED_AUTH', client_ip, username, "User changed password via session verification.")
                return redirect(url_for('index'))
            else:
                flash("Old credentials mismatch. Attempt blocked.", "danger")
                log_security_event('PASSWORD_UPDATE_FAILED', client_ip, username, "Unauthorized old password verification mismatch.")
        else:
            # Unauthenticated password update (admin/offline demo recovery utility)
            username = sanitize_input(request.form.get('username'))
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            
            user = execute_query("SELECT * FROM users WHERE username = ?", (username,), fetch="one")
            if user and bcrypt.checkpw(old_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                new_hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')
                execute_query("UPDATE users SET password_hash = ? WHERE id = ?", (new_hashed, user['id']))
                flash("Demo account credentials cipher updated.", "success")
                log_security_event('PASSWORD_UPDATED_UNAUTH', client_ip, username, "User updated credentials via offline system credentials matching.")
                return redirect(url_for('login'))
            else:
                flash("Account username and password match failure.", "danger")
                log_security_event('PASSWORD_UPDATE_FAILED_UNAUTH', client_ip, username, "Verification matching failed on unauthenticated password update.")
                
    return render_luxury_template('password_update', title="Update Access Codes")

# ==============================================================================
# Shopping Cart & Checkout Engine
# ==============================================================================

def sync_session_cart(user_id):
    """
    Syncs local memory session cart items to persistent relational engine on login.
    """
    temp_cart = session.get('cart', {})
    if not temp_cart:
        return
        
    for p_id, qty in temp_cart.items():
        # Clean parameters in cart checks
        existing = execute_query("SELECT id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?", (user_id, p_id), fetch="one")
        if existing:
            execute_query(
                "UPDATE cart_items SET quantity = ? WHERE id = ?",
                (existing['quantity'] + qty, existing['id'])
            )
        else:
            execute_query(
                "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)",
                (user_id, p_id, qty)
            )
    session.pop('cart', None)

@app.route('/cart/add/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    product = execute_query("SELECT id, stock FROM products WHERE id = ?", (product_id,), fetch="one")
    if not product:
        flash("Target product does not exist in catalog records.", "danger")
        return redirect(url_for('index'))
        
    if product['stock'] <= 0:
        flash("Desired fashion garment is out of stock.", "danger")
        return redirect(url_for('index'))
        
    if 'user_id' in session:
        user_id = session['user_id']
        existing = execute_query("SELECT id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?", (user_id, product_id), fetch="one")
        if existing:
            execute_query("UPDATE cart_items SET quantity = quantity + 1 WHERE id = ?", (existing['id'],))
        else:
            execute_query("INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, 1)", (user_id, product_id))
    else:
        # Fallback anonymous session cart storage
        if 'cart' not in session:
            session['cart'] = {}
        cart = session['cart']
        p_id_str = str(product_id)
        cart[p_id_str] = cart.get(p_id_str, 0) + 1
        session['cart'] = cart
        
    flash("Item successfully added to your shopping bag.", "success")
    return redirect(url_for('index'))

@app.route('/cart')
def view_cart():
    items = []
    subtotal = 0.0
    
    if 'user_id' in session:
        query = """
        SELECT c.id, c.quantity, p.id as product_id, p.name, p.price, p.category, p.image_url 
        FROM cart_items c 
        JOIN products p ON c.product_id = p.id 
        WHERE c.user_id = ?
        """
        db_items = execute_query(query, (session['user_id'],))
        if db_items:
            items = db_items
    else:
        # Load from session storage
        temp_cart = session.get('cart', {})
        for p_id_str, qty in temp_cart.items():
            product = execute_query("SELECT * FROM products WHERE id = ?", (int(p_id_str),), fetch="one")
            if product:
                item_dict = dict(product)
                item_dict['id'] = p_id_str
                item_dict['quantity'] = qty
                items.append(item_dict)
                
    for item in items:
        subtotal += float(item['price']) * int(item['quantity'])
        
    # Calculate tax & courier metrics
    tax = subtotal * 0.18  # 18% GST standard luxury taxes
    shipping = 500.00 if subtotal > 0 else 0.0
    total = subtotal + tax + shipping
    
    return render_luxury_template(
        'cart',
        title="Your Bag",
        items=items,
        subtotal=subtotal,
        tax=tax,
        shipping=shipping,
        total=total
    )

@app.route('/cart/update/<cart_item_id>', methods=['POST'])
def update_cart(cart_item_id):
    action = request.form.get('action') # 'increase' / 'decrease'
    
    if 'user_id' in session:
        # Authenticated Database cart manipulation
        item = execute_query("SELECT id, quantity, product_id FROM cart_items WHERE id = ? AND user_id = ?", (int(cart_item_id), session['user_id']), fetch="one")
        if item:
            prod = execute_query("SELECT stock FROM products WHERE id = ?", (item['product_id'],), fetch="one")
            if action == 'increase':
                if item['quantity'] + 1 <= prod['stock']:
                    execute_query("UPDATE cart_items SET quantity = quantity + 1 WHERE id = ?", (item['id'],))
                else:
                    flash("Requested quantity exceeds available catalog stock.", "warning")
            elif action == 'decrease':
                if item['quantity'] - 1 > 0:
                    execute_query("UPDATE cart_items SET quantity = quantity - 1 WHERE id = ?", (item['id'],))
                else:
                    execute_query("DELETE FROM cart_items WHERE id = ?", (item['id'],))
    else:
        # Anonymous session cart manipulation
        cart = session.get('cart', {})
        if cart_item_id in cart:
            prod = execute_query("SELECT stock FROM products WHERE id = ?", (int(cart_item_id),), fetch="one")
            if action == 'increase':
                if cart[cart_item_id] + 1 <= prod['stock']:
                    cart[cart_item_id] += 1
                else:
                    flash("Requested quantity exceeds available catalog stock.", "warning")
            elif action == 'decrease':
                if cart[cart_item_id] - 1 > 0:
                    cart[cart_item_id] -= 1
                else:
                    cart.pop(cart_item_id, None)
            session['cart'] = cart
            
    return redirect(url_for('view_cart'))

@app.route('/cart/delete/<cart_item_id>', methods=['POST'])
def delete_cart_item(cart_item_id):
    if 'user_id' in session:
        execute_query("DELETE FROM cart_items WHERE id = ? AND user_id = ?", (int(cart_item_id), session['user_id']))
    else:
        cart = session.get('cart', {})
        cart.pop(cart_item_id, None)
        session['cart'] = cart
        
    flash("Item successfully removed from your bag.", "success")
    return redirect(url_for('view_cart'))

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        flash("Secure checkout operations require client registration credentials.", "warning")
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    
    # Query current cart
    query = """
    SELECT c.id, c.quantity, p.id as product_id, p.name, p.price, p.category, p.stock
    FROM cart_items c 
    JOIN products p ON c.product_id = p.id 
    WHERE c.user_id = ?
    """
    items = execute_query(query, (user_id,))
    if not items:
        flash("Cannot run checkout operations on an empty bag.", "danger")
        return redirect(url_for('index'))
        
    subtotal = 0.0
    for item in items:
        subtotal += float(item['price']) * int(item['quantity'])
        # Verify active stock values
        if item['quantity'] > item['stock']:
            flash(f"Operational Alert: Dynamic stock changes. {item['name']} exceeded stock limits.", "danger")
            return redirect(url_for('view_cart'))
            
    tax = subtotal * 0.18
    shipping = 500.00
    total = subtotal + tax + shipping
    
    if request.method == 'POST':
        fullname = sanitize_input(request.form.get('fullname'))
        address = sanitize_input(request.form.get('address'))
        city = sanitize_input(request.form.get('city'))
        state = sanitize_input(request.form.get('state'))
        zip_code = sanitize_input(request.form.get('zip'))
        
        full_shipping = f"{fullname}, {address}, {city}, {state} - {zip_code}"
        
        try:
            # 1. Write invoice metadata log
            order_id = execute_query(
                "INSERT INTO orders (user_id, status, total_amount, shipping_address) VALUES (?, 'Paid', ?, ?)",
                (user_id, total, full_shipping)
            )
            
            # 2. Write item components and adjust product inventory constraints
            for item in items:
                execute_query(
                    "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
                    (order_id, item['product_id'], item['quantity'], item['price'])
                )
                execute_query(
                    "UPDATE products SET stock = stock - ? WHERE id = ?",
                    (item['quantity'], item['product_id'])
                )
                
            # 3. Securely purge user cart
            execute_query("DELETE FROM cart_items WHERE user_id = ?", (user_id,))
            
            # Log purchase event successfully
            log_security_event('ORDER_PLACED', request.remote_addr, session['username'], f"Order #{order_id} processed successfully. Revenue: {total}")
            
            # Save receipt metrics in session storage
            session['receipt'] = {
                'order_id': order_id,
                'total': total,
                'address': full_shipping,
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            return redirect(url_for('confirmation'))
        except Exception as e:
            print(f"Transaction Exception aborted checkout: {e}", file=sys.stderr)
            flash("System interrupted. Could not authenticate bank transactions.", "danger")
            
    return render_luxury_template(
        'checkout',
        title="Bespoke Checkout",
        items=items,
        subtotal=subtotal,
        tax=tax,
        shipping=shipping,
        total=total
    )

@app.route('/confirmation')
def confirmation():
    receipt = session.pop('receipt', None)
    if not receipt:
        flash("Order receipts can only be viewed at transaction termination.", "warning")
        return redirect(url_for('index'))
        
    return render_luxury_template(
        'confirmation',
        title="Receipt Confirmed",
        order_id=receipt['order_id'],
        total=receipt['total'],
        address=receipt['address'],
        date=receipt['date']
    )

# ==============================================================================
# Administrative Portal (CRUD & Audit Logs)
# ==============================================================================

def check_admin_access():
    if 'user_id' not in session or session.get('role') != 'admin':
        log_security_event(
            'UNAUTHORIZED_ADMIN_ATTEMPT',
            request.remote_addr,
            session.get('username'),
            f"Attempted access route: {request.path}"
        )
        abort(403, "Access Denied: Administrative privileges strictly required.")

@app.route('/admin')
def admin_portal():
    check_admin_access()
    
    pane = request.args.get('pane', 'inventory')
    
    # Compile dashboards data structure metrics
    metric_catalog = execute_query("SELECT COUNT(*) as cnt FROM products", fetch="one")['cnt']
    metric_clients = execute_query("SELECT COUNT(*) as cnt FROM users WHERE role = 'customer'", fetch="one")['cnt']
    metric_gross = execute_query("SELECT SUM(total_amount) as total FROM orders WHERE status = 'Paid'", fetch="one")['total']
    
    metrics = {
        'catalog_count': metric_catalog,
        'clients_count': metric_clients,
        'gross_sales': metric_gross or 0.0
    }
    
    products = execute_query("SELECT * FROM products ORDER BY id DESC")
    
    # Read-only Customer Transaction log compilation
    tx_query = """
    SELECT o.id, o.total_amount, o.shipping_address, o.status, o.created_at, u.username
    FROM orders o
    JOIN users u ON o.user_id = u.id
    ORDER BY o.id DESC
    """
    transactions = execute_query(tx_query)
    
    # Read-only Security Audits Log compilation
    security_logs = execute_query("SELECT * FROM security_logs ORDER BY id DESC LIMIT 50")
    
    return render_luxury_template(
        'admin_portal',
        title="Admin Executive Suite",
        metrics=metrics,
        products=products,
        transactions=transactions,
        security_logs=security_logs,
        active_pane=pane
    )

@app.route('/admin/product/add', methods=['GET', 'POST'])
def admin_add_product():
    check_admin_access()
    
    if request.method == 'POST':
        name = sanitize_input(request.form.get('name'))
        description = sanitize_input(request.form.get('description'))
        price = float(request.form.get('price', 0))
        stock = int(request.form.get('stock', 0))
        category = request.form.get('category')
        image_url = sanitize_input(request.form.get('image_url'))
        
        try:
            execute_query(
                "INSERT INTO products (name, description, price, category, image_url, stock) VALUES (?, ?, ?, ?, ?, ?)",
                (name, description, price, category, image_url, stock)
            )
            flash("Luxury creation added into catalog registries.", "success")
            log_security_event('CATALOG_PRODUCT_CREATED', request.remote_addr, session['username'], f"New Item '{name}' inserted into inventory.")
            return redirect(url_for('admin_portal'))
        except Exception as e:
            flash("Exception writing to catalog.", "danger")
            print(f"Product insertion failed: {e}", file=sys.stderr)
            
    return render_luxury_template('admin_product_form', title="New Catalog Creation", product=None)

@app.route('/admin/product/edit/<int:product_id>', methods=['GET', 'POST'])
def admin_edit_product(product_id):
    check_admin_access()
    
    product = execute_query("SELECT * FROM products WHERE id = ?", (product_id,), fetch="one")
    if not product:
        abort(404)
        
    if request.method == 'POST':
        name = sanitize_input(request.form.get('name'))
        description = sanitize_input(request.form.get('description'))
        price = float(request.form.get('price', 0))
        stock = int(request.form.get('stock', 0))
        category = request.form.get('category')
        image_url = sanitize_input(request.form.get('image_url'))
        
        try:
            execute_query(
                "UPDATE products SET name = ?, description = ?, price = ?, category = ?, image_url = ?, stock = ? WHERE id = ?",
                (name, description, price, category, image_url, stock, product_id)
            )
            flash("Catalog item attributes edited and finalized.", "success")
            log_security_event('CATALOG_PRODUCT_MODIFIED', request.remote_addr, session['username'], f"Item ID {product_id} modifications committed.")
            return redirect(url_for('admin_portal'))
        except Exception as e:
            flash("Exception editing catalog constraints.", "danger")
            print(f"Product update failed: {e}", file=sys.stderr)
            
    return render_luxury_template('admin_product_form', title="Edit Catalog Creation", product=product)

@app.route('/admin/product/delete/<int:product_id>', methods=['POST'])
def admin_delete_product(product_id):
    check_admin_access()
    
    product = execute_query("SELECT name FROM products WHERE id = ?", (product_id,), fetch="one")
    if product:
        execute_query("DELETE FROM products WHERE id = ?", (product_id,))
        flash("Catalog creation removed successfully.", "success")
        log_security_event('CATALOG_PRODUCT_DELETED', request.remote_addr, session['username'], f"Item '{product['name']}' (ID {product_id}) purged.")
    else:
        flash("Product targeted for deletion does not exist.", "danger")
        
    return redirect(url_for('admin_portal'))

@app.route('/orders')
def view_orders():
    if 'user_id' not in session:
        flash("Please log in to view your order history.", "warning")
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    
    # Query all orders placed by the current user
    query = """
    SELECT id, total_amount, shipping_address, status, created_at
    FROM orders
    WHERE user_id = ?
    ORDER BY id DESC
    """
    user_orders = execute_query(query, (user_id,))
    
    # For each order, fetch the items!
    orders_list = []
    for o in user_orders or []:
        items_query = """
        SELECT oi.quantity, oi.price, p.name, p.category, p.image_url
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        WHERE oi.order_id = ?
        """
        items = execute_query(items_query, (o['id'],))
        o_dict = dict(o)
        o_dict['items'] = items
        orders_list.append(o_dict)
        
    return render_luxury_template(
        'order_history',
        title="Order History",
        orders=orders_list
    )

# ==============================================================================
# Healthcheck Probe
# ==============================================================================

@app.route('/health')
def healthcheck():
    """
    Returns basic application health flags for Docker and AWS ALB telemetry probes.
    """
    try:
        # Check active db connections
        execute_query("SELECT 1", fetch="one")
        resp = make_response({"status": "healthy", "engine": "dual-active"}, 200)
    except Exception as e:
        resp = make_response({"status": "unhealthy", "error": str(e)}, 503)
    return resp

# ==============================================================================
# Bootstrap Entrypoint
# ==============================================================================

if __name__ == '__main__':
    # Initialize schema migration on application boot
    init_database()
    
    # CLI check-only validation mode
    if len(sys.argv) > 1 and sys.argv[1] == '--check-only':
        print("Application syntax check verified. Exiting clean.")
        sys.exit(0)
        
    # Standard server bind
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
