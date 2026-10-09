import os
import sqlite3
import random
from datetime import datetime, timezone
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production')

DB_PATH = os.environ.get('DB_PATH', 'pick4me.db')
UPI_ID = os.environ.get('UPI_ID', '7387157739@upi')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'abhishekkanadje7@gmail.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')  # set this on Render

# zone: (label, base fee, SLA minutes)
ZONES = {
    'campus': ('Within Campus (0-1 km)', 20, 25),
    'gate': ('Near Gate Market (1-2.5 km)', 35, 35),
    'outer': ('Outer Town Market (2.5-5 km)', 55, 50),
}
RUSH_FEE = 15
SPEED_BONUS = 10
DELAY_PENALTY = 10
STATUS_FLOW = ['accepted', 'picked_up', 'on_the_way']

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('customer','shopper','admin')),
    phone TEXT DEFAULT '',
    verified INTEGER DEFAULT 0,
    wallet REAL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS shops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    category TEXT DEFAULT 'General',
    address TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    description TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop_id INTEGER NOT NULL REFERENCES shops(id),
    name TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT DEFAULT '',
    in_stock INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS cart_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    qty INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL REFERENCES users(id),
    shopper_id INTEGER REFERENCES users(id),
    shop_name TEXT DEFAULT '',
    item_desc TEXT NOT NULL,
    items_total REAL DEFAULT 0,
    delivery_fee REAL DEFAULT 0,
    total REAL DEFAULT 0,
    zone TEXT DEFAULT 'campus',
    rush INTEGER DEFAULT 0,
    is_errand INTEGER DEFAULT 0,
    address TEXT DEFAULT '',
    otp TEXT,
    payment_status TEXT DEFAULT 'pending',
    status TEXT DEFAULT 'awaiting_payment',
    sla_minutes INTEGER DEFAULT 25,
    bonus REAL DEFAULT 0,
    penalty REAL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    accepted_at TEXT,
    delivered_at TEXT
);
CREATE TABLE IF NOT EXISTS wallet_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    order_id INTEGER,
    amount REAL NOT NULL,
    note TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


# ====================================================================
# PART 1: Database + auth helpers + register/login/logout
# ====================================================================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    if ADMIN_PASSWORD:
        exists = db.execute('SELECT 1 FROM users WHERE email=?',
                            (ADMIN_EMAIL,)).fetchone()
        if not exists:
            db.execute(
                "INSERT INTO users (name,email,password_hash,role,verified) "
                "VALUES (?,?,?,?,1)",
                ('Admin', ADMIN_EMAIL,
                    generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256'), 'admin'))
    db.commit()
    db.close()


def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return get_db().execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get('user_id'):
            flash('Please login first.', 'warning')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if not session.get('user_id'):
                flash('Please login first.', 'warning')
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                flash('You do not have access to that page.', 'danger')
                return redirect(url_for('index'))
            return f(*a, **kw)
        return wrapper
    return deco


@app.context_processor
def inject_globals():
    count = 0
    if session.get('user_id') and session.get('role') == 'customer':
        row = get_db().execute(
            'SELECT COALESCE(SUM(qty),0) FROM cart_items WHERE user_id=?',
            (session['user_id'],)).fetchone()
        count = row[0]
    return dict(cart_count=count, session_role=session.get('role'),
                session_name=session.get('name'), upi_id=UPI_ID,
                zones=ZONES)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'customer')
        if role not in ('customer', 'shopper'):
            role = 'customer'
        if not name or not email or len(password) < 6:
            flash('Fill all fields. Password must be at least 6 characters.', 'danger')
            return render_template('auth.html', mode='register')
        db = get_db()
        if db.execute('SELECT 1 FROM users WHERE email=?', (email,)).fetchone():
            flash('This email is already registered.', 'danger')
            return render_template('auth.html', mode='register')
        db.execute(
            'INSERT INTO users (name,email,password_hash,role,phone) VALUES (?,?,?,?,?)',
                        (name, email, generate_password_hash(password, method='pbkdf2:sha256'), role, phone))
        db.commit()
        flash('Account created. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('auth.html', mode='register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = get_db().execute('SELECT * FROM users WHERE email=?',
                                (email,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['name'] = user['name']
            return redirect(url_for('dashboard'))
        flash('Wrong email or password.', 'danger')
    return render_template('auth.html', mode='login')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))


# ====================================================================
# PART 2: Home, cart, checkout, custom errand
# ====================================================================
def calc_fee(zone, rush):
    if zone not in ZONES:
        zone = 'campus'
    label, base, sla = ZONES[zone]
    fee = base + (RUSH_FEE if rush else 0)
    return zone, fee, sla


def new_otp():
    return f"{random.randint(0, 9999):04d}"


@app.route('/')
def index():
    db = get_db()
    q = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()
    shop_id = request.args.get('shop', type=int)
    max_price = request.args.get('max_price', type=float)

    sql = ("SELECT p.*, s.name AS shop_name, s.category AS shop_category "
           "FROM products p JOIN shops s ON s.id = p.shop_id WHERE 1=1")
    params = []
    if q:
        sql += " AND (p.name LIKE ? OR p.description LIKE ?)"
        params += [f'%{q}%', f'%{q}%']
    if category:
        sql += " AND s.category = ?"
        params.append(category)
    if shop_id:
        sql += " AND s.id = ?"
        params.append(shop_id)
    if max_price:
        sql += " AND p.price <= ?"
        params.append(max_price)
    sql += " ORDER BY p.id DESC"
    products = db.execute(sql, params).fetchall()

    shops = db.execute(
        "SELECT s.*, (SELECT COUNT(*) FROM products WHERE shop_id = s.id) "
        "AS product_count FROM shops s ORDER BY s.name").fetchall()
    categories = [r[0] for r in db.execute(
        "SELECT DISTINCT category FROM shops ORDER BY category").fetchall()]
    shop = None
    if shop_id:
        shop = db.execute('SELECT * FROM shops WHERE id=?', (shop_id,)).fetchone()

    return render_template('index.html', products=products, shops=shops,
                           categories=categories, q=q, category=category,
                           shop=shop, max_price=max_price)


CART_SQL = (
    "SELECT c.id, c.qty, p.name, p.price, p.in_stock, "
    "s.name AS shop_name, s.id AS shop_id "
    "FROM cart_items c JOIN products p ON p.id = c.product_id "
    "JOIN shops s ON s.id = p.shop_id "
    "WHERE c.user_id = ? ORDER BY s.id")


@app.route('/cart')
@role_required('customer')
def cart():
    items = get_db().execute(CART_SQL, (session['user_id'],)).fetchall()
    subtotal = sum(i['price'] * i['qty'] for i in items)
    return render_template('cart.html', items=items, subtotal=subtotal)


@app.route('/cart/add', methods=['POST'])
@role_required('customer')
def cart_add():
    pid = request.form.get('product_id', type=int)
    qty = max(1, request.form.get('qty', 1, type=int) or 1)
    db = get_db()
    p = db.execute('SELECT * FROM products WHERE id=?', (pid,)).fetchone()
    if not p or not p['in_stock']:
        flash('Product is not available.', 'danger')
        return redirect(request.referrer or url_for('index'))
    row = db.execute(
        'SELECT id FROM cart_items WHERE user_id=? AND product_id=?',
        (session['user_id'], pid)).fetchone()
    if row:
        db.execute('UPDATE cart_items SET qty = qty + ? WHERE id=?',
                   (qty, row['id']))
    else:
        db.execute('INSERT INTO cart_items (user_id, product_id, qty) VALUES (?,?,?)',
                   (session['user_id'], pid, qty))
    db.commit()
    flash('Added to cart.', 'success')
    return redirect(request.referrer or url_for('index'))


@app.route('/cart/remove/<int:id>', methods=['POST'])
@role_required('customer')
def cart_remove(id):
    db = get_db()
    db.execute('DELETE FROM cart_items WHERE id=? AND user_id=?',
               (id, session['user_id']))
    db.commit()
    flash('Item removed.', 'info')
    return redirect(url_for('cart'))


@app.route('/cart/checkout', methods=['POST'])
@role_required('customer')
def cart_checkout():
    db = get_db()
    uid = session['user_id']
    address = request.form.get('address', '').strip()
    zone, fee, sla = calc_fee(request.form.get('zone'),
                              bool(request.form.get('rush')))
    rush = 1 if request.form.get('rush') else 0

    if not address:
        flash('Please enter a delivery address.', 'danger')
        return redirect(url_for('cart'))

    items = db.execute(CART_SQL, (uid,)).fetchall()
    if not items:
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('cart'))
    if any(not i['in_stock'] for i in items):
        flash('Remove out-of-stock items before checkout.', 'danger')
        return redirect(url_for('cart'))

    groups = {}
    for i in items:
        groups.setdefault(i['shop_id'], []).append(i)

    order_ids = []
    for rows in groups.values():
        items_total = sum(r['price'] * r['qty'] for r in rows)
        desc = ', '.join(f"{r['name']} x{r['qty']}" for r in rows)
        cur = db.execute(
            "INSERT INTO orders (customer_id, shop_name, item_desc, items_total, "
            "delivery_fee, total, zone, rush, address, otp, sla_minutes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (uid, rows[0]['shop_name'], desc, items_total, fee,
             items_total + fee, zone, rush, address, new_otp(), sla))
        order_ids.append(cur.lastrowid)

    db.execute('DELETE FROM cart_items WHERE user_id=?', (uid,))
    db.commit()
    flash('Order placed. Please complete the advance payment.', 'success')
    if len(order_ids) == 1:
        return redirect(url_for('order_detail', id=order_ids[0]))
    return redirect(url_for('orders'))


@app.route('/errand', methods=['GET', 'POST'])
@role_required('customer')
def errand():
    if request.method == 'POST':
        item_desc = request.form.get('item_desc', '').strip()
        shop_name = request.form.get('shop_name', '').strip()
        address = request.form.get('address', '').strip()
        est_cost = max(0.0, request.form.get('est_cost', 0, type=float) or 0.0)
        rush = 1 if request.form.get('rush') else 0
        zone, fee, sla = calc_fee(request.form.get('zone'), rush)

        if not item_desc or not shop_name or not address:
            flash('Item, shop and delivery address are required.', 'danger')
            return render_template('errand.html')

        db = get_db()
        cur = db.execute(
            "INSERT INTO orders (customer_id, shop_name, item_desc, items_total, "
            "delivery_fee, total, zone, rush, is_errand, address, otp, sla_minutes) "
            "VALUES (?,?,?,?,?,?,?,?,1,?,?,?)",
            (session['user_id'], shop_name, item_desc, est_cost, fee,
             est_cost + fee, zone, rush, address, new_otp(), sla))
        db.commit()
        flash('Errand created. Please complete the advance payment.', 'success')
        return redirect(url_for('order_detail', id=cur.lastrowid))
    return render_template('errand.html')


# ====================================================================
# PART 3: Orders, escrow payment, accept, status, OTP + wallet payout
# ====================================================================
def now_str():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def parse_ts(s):
    return datetime.strptime(s, '%Y-%m-%d %H:%M:%S')


@app.route('/orders')
@login_required
def orders():
    db = get_db()
    uid, role = session['user_id'], session['role']
    if role == 'admin':
        rows = db.execute('SELECT * FROM orders ORDER BY id DESC').fetchall()
    elif role == 'shopper':
        rows = db.execute('SELECT * FROM orders WHERE shopper_id=? ORDER BY id DESC',
                          (uid,)).fetchall()
    else:
        rows = db.execute('SELECT * FROM orders WHERE customer_id=? ORDER BY id DESC',
                          (uid,)).fetchall()
    return render_template('orders.html', orders=rows)


@app.route('/orders/<int:id>')
@login_required
def order_detail(id):
    db = get_db()
    uid, role = session['user_id'], session['role']
    order = db.execute('SELECT * FROM orders WHERE id=?', (id,)).fetchone()
    if not order:
        flash('Order not found.', 'danger')
        return redirect(url_for('orders'))

    is_customer = order['customer_id'] == uid
    is_shopper = order['shopper_id'] == uid
    can_see_open = role == 'shopper' and order['status'] == 'open'
    if role != 'admin' and not (is_customer or is_shopper or can_see_open):
        flash('You cannot view this order.', 'danger')
        return redirect(url_for('orders'))

    customer = db.execute('SELECT name, phone FROM users WHERE id=?',
                          (order['customer_id'],)).fetchone()
    shopper = None
    if order['shopper_id']:
        shopper = db.execute('SELECT name, phone FROM users WHERE id=?',
                             (order['shopper_id'],)).fetchone()

    minutes_left = None
    if order['accepted_at'] and order['status'] in STATUS_FLOW:
        elapsed = (datetime.now(timezone.utc).replace(tzinfo=None)
                   - parse_ts(order['accepted_at'])).total_seconds() / 60
        minutes_left = int(order['sla_minutes'] - elapsed)

    return render_template(
        'order_detail.html', order=order, customer=customer, shopper=shopper,
        is_customer=is_customer, is_shopper=is_shopper,
        show_otp=is_customer,  # OTP is only shown to the customer
        zone_label=ZONES.get(order['zone'], ZONES['campus'])[0],
        minutes_left=minutes_left, status_flow=STATUS_FLOW)


@app.route('/orders/<int:id>/pay', methods=['POST'])
@role_required('customer')
def confirm_payment(id):
    db = get_db()
    cur = db.execute(
        "UPDATE orders SET payment_status='escrow', status='open' "
        "WHERE id=? AND customer_id=? AND payment_status='pending'",
        (id, session['user_id']))
    db.commit()
    if cur.rowcount:
        flash('Payment received in escrow. Your order is now visible to shoppers.',
              'success')
    else:
        flash('This order is already paid or not found.', 'info')
    return redirect(url_for('order_detail', id=id))


@app.route('/orders/<int:id>/accept', methods=['POST'])
@role_required('shopper')
def accept_order(id):
    db = get_db()
    user = current_user()
    if not user['verified']:
        flash('Your account is not KYC verified yet. Ask the admin to verify you.',
              'warning')
        return redirect(url_for('dashboard'))
    cur = db.execute(
        "UPDATE orders SET shopper_id=?, status='accepted', accepted_at=? "
        "WHERE id=? AND status='open' AND customer_id != ?",
        (user['id'], now_str(), id, user['id']))
    db.commit()
    if cur.rowcount:
        flash('Order accepted. The SLA timer has started.', 'success')
        return redirect(url_for('order_detail', id=id))
    flash('This order is no longer available.', 'warning')
    return redirect(url_for('dashboard'))


@app.route('/orders/<int:id>/status', methods=['POST'])
@role_required('shopper')
def update_status(id):
    db = get_db()
    new_status = request.form.get('status')
    order = db.execute('SELECT * FROM orders WHERE id=?', (id,)).fetchone()
    if (not order or order['shopper_id'] != session['user_id']
            or new_status not in STATUS_FLOW
            or order['status'] not in STATUS_FLOW):
        flash('Invalid status update.', 'danger')
        return redirect(url_for('orders'))
    if STATUS_FLOW.index(new_status) <= STATUS_FLOW.index(order['status']):
        flash('Status can only move forward.', 'warning')
        return redirect(url_for('order_detail', id=id))
    db.execute('UPDATE orders SET status=? WHERE id=?', (new_status, id))
    db.commit()
    flash('Status updated.', 'success')
    return redirect(url_for('order_detail', id=id))


@app.route('/orders/<int:id>/verify-otp', methods=['POST'])
@role_required('shopper')
def verify_otp(id):
    db = get_db()
    uid = session['user_id']
    order = db.execute('SELECT * FROM orders WHERE id=?', (id,)).fetchone()
    if (not order or order['shopper_id'] != uid
            or order['status'] not in STATUS_FLOW):
        flash('This order cannot be completed.', 'danger')
        return redirect(url_for('orders'))

    entered = request.form.get('otp', '').strip()
    if entered != order['otp']:
        flash('Wrong OTP. Ask the customer for the correct 4-digit code.', 'danger')
        return redirect(url_for('order_detail', id=id))

    # bonus if delivered within 60% of the SLA, penalty if later than the SLA
    delivered_at = now_str()
    elapsed_min = (parse_ts(delivered_at)
                   - parse_ts(order['accepted_at'])).total_seconds() / 60
    bonus = SPEED_BONUS if elapsed_min <= order['sla_minutes'] * 0.6 else 0
    penalty = DELAY_PENALTY if elapsed_min > order['sla_minutes'] else 0
    payout = max(0.0, order['total'] + bonus - penalty)

    # the status check in WHERE makes sure the payout can happen only once
    cur = db.execute(
        "UPDATE orders SET status='delivered', delivered_at=?, bonus=?, penalty=?, "
        "payment_status='released' WHERE id=? AND status IN "
        "('accepted','picked_up','on_the_way')",
        (delivered_at, bonus, penalty, id))
    if cur.rowcount:
        db.execute('UPDATE users SET wallet = wallet + ? WHERE id=?', (payout, uid))
        note = f'Order #{id} delivered'
        if bonus:
            note += f' (+{bonus:g} speed bonus)'
        if penalty:
            note += f' (-{penalty:g} delay penalty)'
        db.execute(
            'INSERT INTO wallet_transactions (user_id, order_id, amount, note) '
            'VALUES (?,?,?,?)', (uid, id, payout, note))
        db.commit()
        flash(f'OTP verified. Rs {payout:g} added to your wallet.', 'success')
    else:
        db.rollback()
        flash('This order was already completed.', 'info')
    return redirect(url_for('order_detail', id=id))


# ====================================================================
# PART 4: Dashboards, admin KYC, merchant, 404, startup
# ====================================================================
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    uid, role = session['user_id'], session['role']
    user = current_user()

    if role == 'customer':
        recent = db.execute(
            'SELECT * FROM orders WHERE customer_id=? ORDER BY id DESC LIMIT 5',
            (uid,)).fetchall()
        stats = {
            'total': db.execute('SELECT COUNT(*) FROM orders WHERE customer_id=?',
                                (uid,)).fetchone()[0],
            'active': db.execute(
                "SELECT COUNT(*) FROM orders WHERE customer_id=? "
                "AND status NOT IN ('delivered')", (uid,)).fetchone()[0],
        }
        return render_template('dashboard.html', role=role, user=user,
                               recent=recent, stats=stats)

    if role == 'shopper':
        open_orders = db.execute(
            "SELECT * FROM orders WHERE status='open' AND customer_id != ? "
            "ORDER BY rush DESC, id DESC", (uid,)).fetchall()
        my_orders = db.execute(
            "SELECT * FROM orders WHERE shopper_id=? AND status != 'delivered' "
            "ORDER BY id DESC", (uid,)).fetchall()
        txns = db.execute(
            'SELECT * FROM wallet_transactions WHERE user_id=? ORDER BY id DESC '
            'LIMIT 20', (uid,)).fetchall()
        delivered = db.execute(
            "SELECT COUNT(*) FROM orders WHERE shopper_id=? AND status='delivered'",
            (uid,)).fetchone()[0]
        return render_template('dashboard.html', role=role, user=user,
                               open_orders=open_orders, my_orders=my_orders,
                               txns=txns, delivered=delivered)

    # admin
    stats = {
        'users': db.execute(
            "SELECT COUNT(*) FROM users WHERE role != 'admin'").fetchone()[0],
        'shops': db.execute('SELECT COUNT(*) FROM shops').fetchone()[0],
        'orders': db.execute('SELECT COUNT(*) FROM orders').fetchone()[0],
        'escrow': db.execute(
            "SELECT COALESCE(SUM(total),0) FROM orders "
            "WHERE payment_status='escrow'").fetchone()[0],
        'released': db.execute(
            "SELECT COALESCE(SUM(total),0) FROM orders "
            "WHERE payment_status='released'").fetchone()[0],
    }
    users = db.execute(
        "SELECT * FROM users WHERE role != 'admin' ORDER BY id DESC").fetchall()
    shops = db.execute(
        'SELECT s.*, u.name AS owner_name FROM shops s '
        'JOIN users u ON u.id = s.owner_id ORDER BY s.id DESC').fetchall()
    all_orders = db.execute(
        'SELECT * FROM orders ORDER BY id DESC LIMIT 20').fetchall()
    return render_template('dashboard.html', role=role, user=user, stats=stats,
                           users=users, shops=shops, all_orders=all_orders)


@app.route('/admin/users/<int:id>/verify', methods=['POST'])
@role_required('admin')
def toggle_verify(id):
    db = get_db()
    db.execute(
        "UPDATE users SET verified = 1 - verified WHERE id=? AND role != 'admin'",
        (id,))
    db.commit()
    flash('KYC status updated.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/merchant', methods=['GET', 'POST'])
@role_required('shopper')
def merchant():
    db = get_db()
    uid = session['user_id']
    shop = db.execute('SELECT * FROM shops WHERE owner_id=?', (uid,)).fetchone()

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        category = request.form.get('category', '').strip() or 'General'
        address = request.form.get('address', '').strip()
        phone = request.form.get('phone', '').strip()
        description = request.form.get('description', '').strip()
        if not name:
            flash('Shop name is required.', 'danger')
            return redirect(url_for('merchant'))
        if shop:
            db.execute(
                'UPDATE shops SET name=?, category=?, address=?, phone=?, '
                'description=? WHERE id=?',
                (name, category, address, phone, description, shop['id']))
        else:
            db.execute(
                'INSERT INTO shops (owner_id,name,category,address,phone,description) '
                'VALUES (?,?,?,?,?,?)',
                (uid, name, category, address, phone, description))
        db.commit()
        flash('Shop saved.', 'success')
        return redirect(url_for('merchant'))

    products = []
    if shop:
        products = db.execute(
            'SELECT * FROM products WHERE shop_id=? ORDER BY id DESC',
            (shop['id'],)).fetchall()
    return render_template('merchant.html', shop=shop, products=products)


@app.route('/merchant/products/add', methods=['POST'])
@role_required('shopper')
def add_product():
    db = get_db()
    shop = db.execute('SELECT id FROM shops WHERE owner_id=?',
                      (session['user_id'],)).fetchone()
    if not shop:
        flash('Create your shop first.', 'warning')
        return redirect(url_for('merchant'))
    name = request.form.get('name', '').strip()
    price = request.form.get('price', type=float)
    if not name or price is None or price < 0:
        flash('Product name and a valid price are required.', 'danger')
        return redirect(url_for('merchant'))
    db.execute(
        'INSERT INTO products (shop_id,name,price,description,in_stock) '
        'VALUES (?,?,?,?,?)',
        (shop['id'], name, price, request.form.get('description', '').strip(),
         1 if request.form.get('in_stock', '1') == '1' else 0))
    db.commit()
    flash('Product added.', 'success')
    return redirect(url_for('merchant'))


@app.route('/merchant/products/<int:id>/delete', methods=['POST'])
@role_required('shopper')
def delete_product(id):
    db = get_db()
    shop = db.execute('SELECT id FROM shops WHERE owner_id=?',
                      (session['user_id'],)).fetchone()
    if shop:
        db.execute('DELETE FROM cart_items WHERE product_id IN '
                   '(SELECT id FROM products WHERE id=? AND shop_id=?)',
                   (id, shop['id']))
        db.execute('DELETE FROM products WHERE id=? AND shop_id=?',
                   (id, shop['id']))
        db.commit()
        flash('Product deleted.', 'info')
    return redirect(url_for('merchant'))


@app.errorhandler(404)
def not_found(e):
    flash('Page not found.', 'warning')
    return redirect(url_for('index'))


init_db()  # runs on import, so it also works with gunicorn on Render

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)