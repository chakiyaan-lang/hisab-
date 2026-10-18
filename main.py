import os, sqlite3, hashlib, secrets, json, re, time
from pathlib import Path
from typing import Optional
from contextlib import contextmanager
import requests
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DB_PATH = os.getenv('DATABASE_PATH', str(ROOT / 'hisabkitab.db'))
SESSION_COOKIE = 'hisabkitab_session'
SESSION_DAYS = int(os.getenv('SESSION_DAYS', '7'))
app = FastAPI(title='Hisab Kitab', version='1.0.0')

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA foreign_keys=ON')
        yield conn
        conn.commit()
    finally:
        conn.close()

def hash_password(password: str, salt: Optional[str] = None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 180_000).hex()
    return salt, digest

def verify_password(password, salt, digest):
    return secrets.compare_digest(hash_password(password, salt)[1], digest)

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, shop_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'shopkeeper', salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, qty INTEGER NOT NULL DEFAULT 0, price REAL NOT NULL DEFAULT 0, cost REAL NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, product_id INTEGER REFERENCES products(id) ON DELETE SET NULL, product_name TEXT NOT NULL, qty INTEGER NOT NULL, total REAL NOT NULL, profit REAL NOT NULL, payment TEXT NOT NULL DEFAULT 'Cash', customer TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, amount REAL NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS udhaar(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, customer TEXT NOT NULL, phone TEXT DEFAULT '', amount REAL NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        ''')
        email = os.getenv('ADMIN_EMAIL', 'admin@hisabkitab.local').strip().lower()
        password = os.getenv('ADMIN_PASSWORD', 'ChangeMe-Admin-123!')
        row = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        if not row:
            salt, digest = hash_password(password)
            c.execute('INSERT INTO users(email,name,shop_name,role,salt,password_hash) VALUES(?,?,?,?,?,?)', (email, 'Hisab Kitab Administrator', 'Hisab Kitab Admin', 'admin', salt, digest))

init_db()

class AuthIn(BaseModel):
    email: str
    password: str
    name: Optional[str] = ''
    shop_name: Optional[str] = ''
    mode: str = 'login'
class ProductIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    qty: int = Field(ge=0, le=10000000)
    price: float = Field(ge=0, le=100000000)
    cost: float = Field(ge=0, le=100000000)
class SaleIn(BaseModel):
    product_id: int
    qty: int = Field(gt=0, le=100000)
    payment: str = 'Cash'
    customer: Optional[str] = ''
class ExpenseIn(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    amount: float = Field(gt=0, le=100000000)
class UdhaarIn(BaseModel):
    customer: str = Field(min_length=1, max_length=100)
    phone: Optional[str] = ''
    amount: float = Field(gt=0, le=100000000)
class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
class RepayIn(BaseModel):
    amount: float = Field(gt=0, le=100000000)

@app.middleware('http')
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

def current_user(request: Request):
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        raise HTTPException(401, 'Please sign in first.')
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    with db() as c:
        row = c.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?', (token_hash, int(time.time()))).fetchone()
    if not row:
        raise HTTPException(401, 'Session expired. Please sign in again.')
    return dict(row)

def admin_user(user=Depends(current_user)):
    if user['role'] != 'admin': raise HTTPException(403, 'Admin access required.')
    return user

def user_payload(u):
    return {'id':u['id'],'email':u['email'],'name':u['name'],'shop_name':u['shop_name'],'role':u['role']}

def seed_products(user_id):
    with db() as c:
        count = c.execute('SELECT COUNT(*) n FROM products WHERE user_id=?', (user_id,)).fetchone()['n']
        if count == 0:
            c.executemany('INSERT INTO products(user_id,name,qty,price,cost) VALUES(?,?,?,?,?)', [
                (user_id,'Milk 1L',24,220,185),(user_id,'Bread',18,160,125),(user_id,'Biscuit Pack',36,80,55),(user_id,'Cooking Oil 1L',9,590,520),(user_id,'Rice 1kg',14,330,280)])

@app.get('/', response_class=HTMLResponse)
def home():
    return (ROOT/'static'/'index.html').read_text(encoding='utf-8')

@app.post('/api/auth')
def auth(payload: AuthIn, response: Response):
    email = payload.email.strip().lower()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email): raise HTTPException(400, 'Enter a valid email address.')
    if len(payload.password) < 8: raise HTTPException(400, 'Password must be at least 8 characters.')
    with db() as c:
        if payload.mode == 'signup':
            if not payload.name.strip() or not payload.shop_name.strip(): raise HTTPException(400, 'Enter your name and shop name.')
            salt, digest = hash_password(payload.password)
            try:
                cur = c.execute('INSERT INTO users(email,name,shop_name,role,salt,password_hash) VALUES(?,?,?,?,?,?)', (email,payload.name.strip()[:100],payload.shop_name.strip()[:100],'shopkeeper',salt,digest))
            except sqlite3.IntegrityError: raise HTTPException(409, 'This email already has an account. Sign in instead.')
            user_id = cur.lastrowid
        else:
            u = c.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
            if not u or not verify_password(payload.password,u['salt'],u['password_hash']): raise HTTPException(401, 'Email or password is incorrect.')
            user_id = u['id']
        raw = secrets.token_urlsafe(36)
        c.execute('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)', (hashlib.sha256(raw.encode()).hexdigest(),user_id,int(time.time())+SESSION_DAYS*86400))
        user = c.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
    if payload.mode == 'signup': seed_products(user_id)
    response.set_cookie(SESSION_COOKIE, raw, httponly=True, secure=os.getenv('COOKIE_SECURE','0')=='1', samesite='lax', max_age=SESSION_DAYS*86400, path='/')
    return {'user':user_payload(dict(user))}

@app.post('/api/logout')
def logout(request: Request, response: Response):
    raw=request.cookies.get(SESSION_COOKIE)
    if raw:
        with db() as c: c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(raw.encode()).hexdigest(),))
    response.delete_cookie(SESSION_COOKIE, path='/')
    return {'ok':True}

@app.get('/api/me')
def me(user=Depends(current_user)): return {'user':user_payload(user)}

@app.get('/api/summary')
def summary(user=Depends(current_user)):
    with db() as c:
        sales=c.execute('SELECT COALESCE(SUM(total),0) n, COALESCE(SUM(profit),0) p, COUNT(*) count FROM sales WHERE user_id=? AND date(created_at)=date(\'now\',\'localtime\')',(user['id'],)).fetchone()
        allprofit=c.execute('SELECT COALESCE(SUM(profit),0) n FROM sales WHERE user_id=?',(user['id'],)).fetchone()['n']
        expenses=c.execute('SELECT COALESCE(SUM(amount),0) n FROM expenses WHERE user_id=?',(user['id'],)).fetchone()['n']
        stock=c.execute('SELECT COALESCE(SUM(qty),0) n, COUNT(*) count FROM products WHERE user_id=?',(user['id'],)).fetchone()
        debt=c.execute('SELECT COALESCE(SUM(amount),0) n FROM udhaar WHERE user_id=?',(user['id'],)).fetchone()['n']
        recent=c.execute('SELECT product_name,qty,total,payment,created_at FROM sales WHERE user_id=? ORDER BY id DESC LIMIT 7',(user['id'],)).fetchall()
    return {'today_sales':sales['n'],'today_profit':sales['p'],'today_transactions':sales['count'],'gross_profit':allprofit,'expenses':expenses,'net_estimate':allprofit-expenses,'stock_units':stock['n'],'product_count':stock['count'],'udhaar':debt,'recent':[dict(x) for x in recent]}

@app.get('/api/products')
def products(user=Depends(current_user)):
    with db() as c: rows=c.execute('SELECT id,name,qty,price,cost FROM products WHERE user_id=? ORDER BY name',(user['id'],)).fetchall()
    return [dict(r) for r in rows]
@app.post('/api/products')
def add_product(p: ProductIn,user=Depends(current_user)):
    with db() as c:
        cur=c.execute('INSERT INTO products(user_id,name,qty,price,cost) VALUES(?,?,?,?,?)',(user['id'],p.name.strip(),p.qty,p.price,p.cost))
        row=c.execute('SELECT id,name,qty,price,cost FROM products WHERE id=?',(cur.lastrowid,)).fetchone()
    return dict(row)
@app.patch('/api/products/{product_id}')
def update_product(product_id:int,p:ProductIn,user=Depends(current_user)):
    with db() as c:
        cur=c.execute('UPDATE products SET name=?,qty=?,price=?,cost=? WHERE id=? AND user_id=?',(p.name.strip(),p.qty,p.price,p.cost,product_id,user['id']))
        if not cur.rowcount: raise HTTPException(404,'Product not found.')
        return dict(c.execute('SELECT id,name,qty,price,cost FROM products WHERE id=?',(product_id,)).fetchone())
@app.delete('/api/products/{product_id}')
def delete_product(product_id:int,user=Depends(current_user)):
    with db() as c:
        cur=c.execute('DELETE FROM products WHERE id=? AND user_id=?',(product_id,user['id']))
        if not cur.rowcount: raise HTTPException(404,'Product not found.')
    return {'ok':True}

@app.get('/api/sales')
def sales(user=Depends(current_user)):
    with db() as c: rows=c.execute('SELECT id,product_name,qty,total,profit,payment,customer,created_at FROM sales WHERE user_id=? ORDER BY id DESC LIMIT 100',(user['id'],)).fetchall()
    return [dict(r) for r in rows]
@app.post('/api/sales')
def add_sale(s:SaleIn,user=Depends(current_user)):
    with db() as c:
        p=c.execute('SELECT * FROM products WHERE id=? AND user_id=?',(s.product_id,user['id'])).fetchone()
        if not p: raise HTTPException(404,'Product not found.')
        if p['qty']<s.qty: raise HTTPException(400,f"Not enough stock. Only {p['qty']} left.")
        total=round(p['price']*s.qty,2); profit=round((p['price']-p['cost'])*s.qty,2)
        c.execute('UPDATE products SET qty=qty-? WHERE id=? AND user_id=?',(s.qty,s.product_id,user['id']))
        c.execute('INSERT INTO sales(user_id,product_id,product_name,qty,total,profit,payment,customer) VALUES(?,?,?,?,?,?,?,?)',(user['id'],p['id'],p['name'],s.qty,total,profit,s.payment,s.customer.strip() if s.customer else None))
        if s.payment.lower()=='udhaar' and s.customer.strip():
            existing=c.execute('SELECT id FROM udhaar WHERE user_id=? AND lower(customer)=lower(?)',(user['id'],s.customer.strip())).fetchone()
            if existing: c.execute('UPDATE udhaar SET amount=amount+? WHERE id=?',(total,existing['id']))
            else: c.execute('INSERT INTO udhaar(user_id,customer,amount) VALUES(?,?,?)',(user['id'],s.customer.strip(),total))
    return {'ok':True,'total':total,'profit':profit,'remaining_stock':p['qty']-s.qty}

@app.get('/api/expenses')
def expenses(user=Depends(current_user)):
    with db() as c: return [dict(r) for r in c.execute('SELECT id,title,amount,created_at FROM expenses WHERE user_id=? ORDER BY id DESC LIMIT 100',(user['id'],)).fetchall()]
@app.post('/api/expenses')
def add_expense(e:ExpenseIn,user=Depends(current_user)):
    with db() as c:
        cur=c.execute('INSERT INTO expenses(user_id,title,amount) VALUES(?,?,?)',(user['id'],e.title.strip(),e.amount))
        return dict(c.execute('SELECT id,title,amount,created_at FROM expenses WHERE id=?',(cur.lastrowid,)).fetchone())
@app.get('/api/udhaar')
def udhaar(user=Depends(current_user)):
    with db() as c: return [dict(r) for r in c.execute('SELECT id,customer,phone,amount,created_at FROM udhaar WHERE user_id=? ORDER BY amount DESC',(user['id'],)).fetchall()]
@app.post('/api/udhaar')
def add_udhaar(u:UdhaarIn,user=Depends(current_user)):
    with db() as c:
        row=c.execute('SELECT id FROM udhaar WHERE user_id=? AND lower(customer)=lower(?)',(user['id'],u.customer.strip())).fetchone()
        if row: c.execute('UPDATE udhaar SET amount=amount+?,phone=? WHERE id=?',(u.amount,u.phone or '',row['id'])); ident=row['id']
        else: ident=c.execute('INSERT INTO udhaar(user_id,customer,phone,amount) VALUES(?,?,?,?)',(user['id'],u.customer.strip(),u.phone or '',u.amount)).lastrowid
        return dict(c.execute('SELECT id,customer,phone,amount,created_at FROM udhaar WHERE id=?',(ident,)).fetchone())
@app.post('/api/udhaar/{debt_id}/repay')
def repay(debt_id:int,p:RepayIn,user=Depends(current_user)):
    with db() as c:
        row=c.execute('SELECT * FROM udhaar WHERE id=? AND user_id=?',(debt_id,user['id'])).fetchone()
        if not row: raise HTTPException(404,'Customer balance not found.')
        if p.amount > row['amount']: raise HTTPException(400,'Repayment cannot exceed the current balance.')
        remaining=round(row['amount']-p.amount,2)
        if remaining <= 0: c.execute('DELETE FROM udhaar WHERE id=? AND user_id=?',(debt_id,user['id']))
        else: c.execute('UPDATE udhaar SET amount=? WHERE id=? AND user_id=?',(remaining,debt_id,user['id']))
    return {'ok':True,'remaining':remaining}

@app.get('/api/admin/users')
def admin_users(user=Depends(admin_user)):
    with db() as c: return [dict(r) for r in c.execute('SELECT id,email,name,shop_name,role,created_at FROM users ORDER BY id DESC').fetchall()]

SYSTEM_PROMPT = "You are Hisab Kitab, a careful digital shop manager for Pakistani retailers. Understand Urdu, Roman Urdu, Punjabi and English. Answer concisely. Use only the supplied shop data for business figures; never invent numbers. Distinguish sales revenue, gross profit, expenses, and estimated net result. Before a destructive or ambiguous stock/sale action, ask a clarification. This endpoint is for advice and reports; sales are only recorded through explicit sale forms."
def local_answer(msg, s, products, debts, expenses):
    q=msg.lower()
    if any(x in q for x in ['sale','sales','bikri','aaj ki kamai','revenue']): return f"Aaj ki sales Rs. {s['today_sales']:,.0f} hain, {s['today_transactions']} transactions hui hain. Total gross profit (all recorded sales) Rs. {s['gross_profit']:,.0f} hai."
    if any(x in q for x in ['stock','inventory','maal','kitna bacha']):
        low=[f"{p['name']} ({p['qty']} left)" for p in products if p['qty']<10]
        return f"Total stock {s['stock_units']} units, {s['product_count']} products. " + ('Low stock: '+', '.join(low)+'.' if low else 'Abhi 10 se kam stock wala product nahi hai.')
    if any(x in q for x in ['udhaar','credit','qarz']): return f"Total recorded udhaar Rs. {s['udhaar']:,.0f} hai, {len(debts)} customers ke records hain."
    if any(x in q for x in ['expense','kharcha','kharchay']): return f"Recorded expenses Rs. {s['expenses']:,.0f}. Gross profit Rs. {s['gross_profit']:,.0f}. Expenses ke baad estimated result Rs. {s['net_estimate']:,.0f}."
    if any(x in q for x in ['profit','munafa','faida']): return f"Gross profit Rs. {s['gross_profit']:,.0f}; recorded expenses Rs. {s['expenses']:,.0f}; expenses ke baad estimated result Rs. {s['net_estimate']:,.0f}. Other costs may not be included."
    return "Main Hisab Kitab shop assistant hoon. Aap pooch sakte hain: 'Aaj ki sale batao', 'Stock check karo', 'Udhaar kitna hai', ya 'Kharchay kitne hain'. Real AI replies ke liye deployment mein HF_TOKEN set karein."

@app.post('/api/assistant')
def assistant(chat:ChatIn,user=Depends(current_user)):
    with db() as c:
        salesrow=c.execute('SELECT COALESCE(SUM(total),0) sales,COALESCE(SUM(profit),0) profit,COUNT(*) n FROM sales WHERE user_id=? AND date(created_at)=date(\'now\',\'localtime\')',(user['id'],)).fetchone()
        gross=c.execute('SELECT COALESCE(SUM(profit),0) n FROM sales WHERE user_id=?',(user['id'],)).fetchone()['n']
        exp=c.execute('SELECT COALESCE(SUM(amount),0) n FROM expenses WHERE user_id=?',(user['id'],)).fetchone()['n']
        prod=[dict(r) for r in c.execute('SELECT name,qty,price,cost FROM products WHERE user_id=?',(user['id'],)).fetchall()]
        debt=[dict(r) for r in c.execute('SELECT customer,amount FROM udhaar WHERE user_id=?',(user['id'],)).fetchall()]
    summary_data={'today_sales':salesrow['sales'],'today_transactions':salesrow['n'],'gross_profit':gross,'expenses':exp,'net_estimate':gross-exp,'stock_units':sum(p['qty'] for p in prod),'product_count':len(prod),'udhaar':sum(d['amount'] for d in debt)}
    token=os.getenv('HF_TOKEN','').strip()
    if token:
        model=os.getenv('HF_MODEL','Qwen/Qwen2.5-7B-Instruct')
        try:
            r=requests.post('https://router.huggingface.co/v1/chat/completions',headers={'Authorization':f'Bearer {token}','Content-Type':'application/json'},json={'model':model,'messages':[{'role':'system','content':SYSTEM_PROMPT+'\nCurrent shop data: '+json.dumps({'summary':summary_data,'products':prod,'udhaar':debt},ensure_ascii=False)},{'role':'user','content':chat.message}],'temperature':0.3,'max_tokens':350},timeout=35)
            if r.ok:
                answer=r.json()['choices'][0]['message']['content'].strip()
                if answer: return {'answer':answer,'mode':'ai'}
        except Exception:
            pass
    return {'answer':local_answer(chat.message,summary_data,prod,debt,[]),'mode':'rules'}

@app.get('/api/health')
def health(): return {'ok':True,'app':'Hisab Kitab','ai':'huggingface' if os.getenv('HF_TOKEN') else 'rules-fallback'}

app.mount('/static', StaticFiles(directory=ROOT/'static'), name='static')
