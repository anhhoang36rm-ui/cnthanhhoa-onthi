from flask import Flask, render_template_string, jsonify, request, redirect, make_response, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import os
import uuid
import random
import string
import json
import smtplib
import hashlib
from email.message import EmailMessage
from datetime import datetime, timedelta
import socket
import calendar
import time
import re
import io
import urllib.parse


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or os.urandom(32)

if os.getenv("TRUST_PROXY", "0") == "1":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def _cookie_is_secure():
    try:
        return bool(request.is_secure)
    except Exception:
        return False


def set_app_cookie(resp, key, value, max_age):
    resp.set_cookie(key, value, max_age=max_age, httponly=True, samesite="Lax", secure=_cookie_is_secure())


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if _cookie_is_secure():
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)
DEVICES_FILE = os.path.join(DATA_DIR, "devices.json")

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)


def _get_db_engine():
    if not DATABASE_URL:
        return None
    try:
        from sqlalchemy import create_engine
        return create_engine(DATABASE_URL, pool_pre_ping=True)
    except Exception:
        return None


ADMIN_CONFIG_FILE = os.path.join(DATA_DIR, "admin_config.json")


def load_admin_password():
    default_password = "admin123"
    engine = _get_db_engine()
    if engine is not None:
        try:
            df = pd.read_sql("SELECT value FROM admin_config WHERE key = 'admin_password'", engine)
            if not df.empty:
                pw = str(df.iloc[0]["value"]).strip()
                if pw:
                    return pw
        except Exception:
            pass

    if not os.path.exists(ADMIN_CONFIG_FILE):
        return default_password
    try:
        with open(ADMIN_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        pw = str((data or {}).get("admin_password") or "").strip()
        return pw if pw else default_password
    except Exception:
        return default_password


def save_admin_password(new_password):
    engine = _get_db_engine()
    if engine is not None:
        try:
            df = pd.DataFrame([{"key": "admin_password", "value": new_password}])
            df.to_sql("admin_config", engine, if_exists="replace", index=False)
        except Exception:
            pass

    try:
        with open(ADMIN_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump({"admin_password": new_password}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


ADMIN_PASSWORD = load_admin_password()

LOGIN_ATTEMPTS = {}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 600


def is_login_rate_limited(key):
    now = time.time()
    attempts = [t for t in LOGIN_ATTEMPTS.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    LOGIN_ATTEMPTS[key] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_failed_login(key):
    LOGIN_ATTEMPTS.setdefault(key, []).append(time.time())


def clear_failed_login(key):
    LOGIN_ATTEMPTS.pop(key, None)


USED_QUESTIONS_FILE = os.path.join(DATA_DIR, "used_questions.json")


def load_used_questions():
    engine = _get_db_engine()
    if engine is not None:
        try:
            df = pd.read_sql("SELECT * FROM used_questions", engine)
            result = {}
            for _, row in df.iterrows():
                email = str(row["email"])
                fname = str(row["fname"])
                qid = int(row["qid"])
                result.setdefault(email, {}).setdefault(fname, set()).add(qid)
            return result
        except Exception:
            pass

    if not os.path.exists(USED_QUESTIONS_FILE):
        return {}
    try:
        with open(USED_QUESTIONS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {}
    result = {}
    if isinstance(raw, dict):
        for email, files in raw.items():
            if not isinstance(files, dict):
                continue
            result[email] = {}
            for fname, ids in files.items():
                try:
                    result[email][fname] = set(int(i) for i in ids)
                except Exception:
                    result[email][fname] = set()
    return result


def save_used_questions():
    engine = _get_db_engine()
    if engine is not None:
        try:
            records = []
            for email, files in SESSION_USED_QUESTIONS.items():
                for fname, ids in files.items():
                    for qid in ids:
                        records.append({"email": email, "fname": fname, "qid": int(qid)})
            df = pd.DataFrame(records, columns=["email", "fname", "qid"])
            df.to_sql("used_questions", engine, if_exists="replace", index=False)
        except Exception:
            pass

    try:
        serializable = {
            email: {fname: sorted(list(ids)) for fname, ids in files.items()}
            for email, files in SESSION_USED_QUESTIONS.items()
        }
        with open(USED_QUESTIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(serializable, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


SESSION_USED_QUESTIONS = load_used_questions()
ADMIN_LOGIN_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1">
  <title>Đăng nhập quản trị</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: Arial, sans-serif; background:#f6f6f6; margin:0; padding:24px 16px; }
    .box { width:100%; max-width:420px; margin:auto; background:white; padding:24px; border-radius:12px; box-shadow:0 8px 24px rgba(0,0,0,.12); }
    h2 { margin-top:0; color:#7a0026; }
    input { width:100%; padding:12px; margin:10px 0 14px; border:1px solid #ddd; border-radius:8px; font-size:16px; }
    button { width:100%; padding:12px; border:none; border-radius:8px; background:#7a0026; color:white; font-weight:bold; cursor:pointer; font-size:16px; }
    .note { margin-top:10px; color:#666; font-size:14px; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Đăng nhập quản trị</h2>
    <form method="get" action="/admin">
      <label for="pwd">Mật khẩu admin</label>
      <input id="pwd" name="pwd" type="password" placeholder="Nhập mật khẩu quản trị" required>
      <button type="submit">Đăng nhập</button>
    </form>
    {% if error %}<p style="color:#b91c1c; margin-top:10px;">{{ error }}</p>{% endif %}
  </div>
</body>
</html>
"""

ADMIN_EMAILS = [e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "admin").split(",") if e.strip()]
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
MAIL_FROM = os.getenv("MAIL_FROM", MAIL_USERNAME)
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"

HTML_LOGIN = r"""
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1">
<title>Đăng nhập</title>
<style>
:root {
  --primary:#7a0026;
  --primary-dark:#5c001f;
  --bg:#f5eff0;
  --card:#ffffff;
  --text:#2c2c2c;
  --muted:#6d6d6d;
}
* {box-sizing:border-box;}
html, body { height:100%; }
body {
  margin:0;
  min-height:100vh;
  min-height:100dvh;
  font-family: "Segoe UI", Arial, sans-serif;
  color: var(--text);
  background: radial-gradient(circle at top left, rgba(122,0,38,0.14) 0%, transparent 32%),
              linear-gradient(180deg, #ffffff 0%, #f5eff0 100%);
  display:flex;
  align-items:center;
  justify-content:center;
  padding:16px;
}
.wrapper {
  width:100%;
  max-width:380px;
}
.card {
  background:var(--card);
  border-radius:20px;
  box-shadow:0 20px 60px rgba(0,0,0,.12);
  overflow:hidden;
}
.top-bar {
  background: linear-gradient(135deg, #7a0026 0%, #b81e4f 100%);
  padding:20px 16px 16px;
  text-align:center;
}
.top-bar img {
  width:56px;
  height:56px;
  border-radius:14px;
  background:#fff;
  display:block;
  margin:0 auto 10px;
  padding:8px;
}
.top-bar h1 {
  margin:0;
  font-size:17px;
  color:#fff;
  letter-spacing:.4px;
  line-height:1.3;
}
.top-bar p {
  margin:10px 0 0;
  color: rgba(255,255,255,.88);
  font-size:13px;
}
.body {
  padding:20px 16px 18px;
  position:relative;
}
.section-title {
  margin:0 0 16px;
  font-size:19px;
  text-align:center;
  color:#7a0026;
  letter-spacing:.4px;
}
.form-group {margin-bottom:14px;}
label {
  display:block;
  margin-bottom:8px;
  font-weight:600;
  color:var(--text);
  font-size:13px;
}
input {
  width:100%;
  padding:12px;
  border:1px solid #e3d3cc;
  border-radius:10px;
  font-size:16px;
  color:var(--text);
  background:#fff;
}
input::placeholder {color:#a19998; font-size:14px;}
input:focus {
  border-color: var(--primary);
  outline:none;
  box-shadow:0 0 0 3px rgba(122,0,38,.12);
}
.button-group {
  display:flex;
  gap:12px;
  justify-content:center;
}
button {
  width:100%;
  display:block;
  padding:12px 14px;
  border:none;
  border-radius:10px;
  font-size:15px;
  font-weight:700;
  cursor:pointer;
}
.primary-btn, .secondary-btn {flex:1;}
.primary-btn {
  background: var(--primary);
  color:#fff;
}
.primary-btn:hover, .primary-btn:active {background: var(--primary-dark);}
.secondary-btn {
  background:#faf5f5;
  color:#4a4a4a;
}
.secondary-btn:hover, .secondary-btn:active {background:#f0e7e8;}
.message {min-height:20px; margin:12px 0 0; font-size:14px; text-align:center; word-break:break-word;}
.message.success {color:#0f6a4f;}
.message.error {color:#b91c1c;}
.switch-link {
  margin-top:12px;
  text-align:center;
  font-size:14px;
  color:var(--muted);
}
.switch-link a {
  color: var(--primary);
  text-decoration:none;
  font-weight:700;
}
.switch-link a:hover {text-decoration:underline;}
.hidden {display:none !important;}

.form-panel{
  transition:opacity 200ms ease;
  opacity:0;
}
.form-panel.visible{opacity:1;}
.footer-text {
  margin-top:14px;
  text-align:center;
  color:#6b6b6b;
  font-size:12px;
  padding:0 12px 16px;
}
.note {
  margin-top:16px;
  padding:10px 12px;
  border-radius:10px;
  background:#fff5f6;
  color:#5a2d3b;
  font-size:12px;
  line-height:1.5;
}
@media (max-width: 400px) {
  body {padding:10px;}
  .top-bar {padding:16px 12px 12px;}
  .body {padding:16px 12px 14px;}
  .top-bar img {width:48px; height:48px;}
  .top-bar h1 {font-size:15px;}
  .section-title {font-size:17px;}
}
@media (min-width: 600px) {
  .wrapper {max-width:420px;}
}
</style>
</head>
<body>
<div class="wrapper">
  <div class="card">
    <div class="top-bar">
      <img src="/logo.png" alt="logo">
        <div class="top-text">
          <h1>AGRIBANK CHI NHÁNH THANH HÓA</h1>        
        </div>
    </div>
    <div class="body">
      <div id="loginDiv" class="form-panel visible" aria-hidden="false">
        <h2 class="section-title">ÔN THI NGHIỆP VỤ</h2>
        <div class="form-group">
          <label for="loginEmail">Email</label>
          <input type="email" id="loginEmail" inputmode="email" autocomplete="username" placeholder="ví dụ: nguyenvanA@agribank.com.vn">
        </div>
        <div class="form-group">
          <label for="loginPassword">Mật khẩu</label>
          <input type="password" id="loginPassword" autocomplete="current-password" placeholder="Nhập mật khẩu">
        </div>
        <div class="button-group">
          <button id="loginBtn" class="primary-btn">Đăng nhập</button>
        </div>
        <div class="switch-link">
          <a href="#" id="showRegisterLink">Chưa có tài khoản? Đăng ký ngay</a>
        </div>
        <p id="msg" class="message error"></p>
        <div id="otherDeviceInfo" class="hidden">
          <button id="clearOtherDeviceBtn" class="secondary-btn">Xóa đăng nhập cũ</button>
          <p class="note" style="margin-top:10px;">Nếu bạn đã đăng xuất trên thiết bị cũ nhưng vẫn gặp lỗi, hãy bấm nút này để xóa phiên đăng nhập cũ.</p>
        </div>
      </div>

      <div id="registerDiv" class="form-panel hidden" aria-hidden="true">
        <h2 class="section-title">ĐĂNG KÝ</h2>
        <div class="form-group">
          <label for="registerEmail">Email</label>
          <input type="email" id="registerEmail" inputmode="email" autocomplete="username" placeholder="ví dụ: nguyenvanA@agribank.com.vn">
        </div>
        <div class="button-group">
          <button id="registerBtn" class="primary-btn">Gửi đăng ký</button>
        </div>
        <div class="switch-link">
          <a href="#" id="showLoginLink">Đã có tài khoản? Đăng nhập</a>
        </div>
        <p id="registerMsg" class="message error"></p>
      </div>
    </div>
    <div class="footer-text" style="color: #A9002B">Copyright © 2026 tuanhaminh@agribank.com.vn</div>
  </div>
</div>
<script>
function showMessage(el, text, type='error') {
  el.textContent = text;
  el.className = 'message ' + (type === 'success' ? 'success' : 'error');
}

function isValidEmail(email) {
  const normalized = (email || '').toLowerCase();
  return normalized === 'admin' || /^\S+@(agribank\.com\.vn|gmail\.com)$/.test(normalized);
}

function showPanel(panelToShow) {
  const loginDiv = document.getElementById("loginDiv");
  const registerDiv = document.getElementById("registerDiv");
  const showLogin = panelToShow === "login";

  loginDiv.classList.toggle("visible", showLogin);
  loginDiv.classList.toggle("hidden", !showLogin);
  registerDiv.classList.toggle("visible", !showLogin);
  registerDiv.classList.toggle("hidden", showLogin);
  loginDiv.setAttribute("aria-hidden", showLogin ? "false" : "true");
  registerDiv.setAttribute("aria-hidden", showLogin ? "true" : "false");
}

async function handleLogin(){
  const email = document.getElementById("loginEmail").value.trim();
  const password = document.getElementById("loginPassword").value.trim();
  const msg = document.getElementById("msg");
  const otherDeviceInfo = document.getElementById("otherDeviceInfo");
  if(!email){ showMessage(msg, "Vui lòng nhập email."); otherDeviceInfo.classList.add('hidden'); return; }
  if(!password){ showMessage(msg, "Vui lòng nhập mật khẩu."); otherDeviceInfo.classList.add('hidden'); return; }
  if(!isValidEmail(email)){
    showMessage(msg, "Email không hợp lệ.");
    otherDeviceInfo.classList.add('hidden');
    return;
  }
  const res = await fetch("/login", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email, password})});
  const data = await res.json();
  showMessage(msg, data.msg, data.success ? 'success' : 'error');
  if(data.success) {
    otherDeviceInfo.classList.add('hidden');
    if(data.admin){
      window.location.href = "/admin";
    }else{
      window.location.href = "/quiz";
    }
    return;
  }
  if(data.otherDevice){
    otherDeviceInfo.classList.remove('hidden');
  } else {
    otherDeviceInfo.classList.add('hidden');
  }
}

async function handleRegister(){
  const email = document.getElementById("registerEmail").value.trim();
  const msg = document.getElementById("registerMsg");
  if(!email){ showMessage(msg, "Vui lòng nhập email."); return; }
  if(!isValidEmail(email)){
    showMessage(msg, "Email không hợp lệ.");
    return;
  }
  const res = await fetch("/register", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email})});
  const data = await res.json();
  showMessage(msg, data.msg, data.success ? 'success' : 'error');
  if(data.success){
    document.getElementById("registerEmail").value = "";
  }
}

document.getElementById("loginBtn").onclick = handleLogin;
document.getElementById("loginEmail").addEventListener("keydown", (e)=>{ if(e.key === "Enter") handleLogin(); });
document.getElementById("loginPassword").addEventListener("keydown", (e)=>{ if(e.key === "Enter") handleLogin(); });
document.getElementById("registerBtn").onclick = handleRegister;
document.getElementById("registerEmail").addEventListener("keydown", (e)=>{ if(e.key === "Enter") handleRegister(); });
document.getElementById("showRegisterLink").onclick = (e)=>{ e.preventDefault(); showPanel("register"); };
document.getElementById("showLoginLink").onclick = (e)=>{ e.preventDefault(); showPanel("login"); };

document.getElementById("clearOtherDeviceBtn").onclick = async () => {
  const email = document.getElementById("loginEmail").value.trim();
  const msg = document.getElementById("msg");
  const otherDeviceInfo = document.getElementById("otherDeviceInfo");
  if(!email){ showMessage(msg, "Vui lòng nhập email trước."); return; }
  const res = await fetch("/clear_session", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email})});
  const data = await res.json();
  showMessage(msg, data.msg, data.success ? 'success' : 'error');
  if(data.success){
    otherDeviceInfo.classList.add('hidden');
  }
};
</script>
</body>
</html>
"""

@app.route('/logo.png')
def logo():
    return send_from_directory(os.path.dirname(__file__), 'logo.png')

HTML_QUIZ = r"""
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1">
<title>ÔN THI NGHIỆP VỤ</title>
<style>
* {box-sizing:border-box;}
body {font-family: Arial, sans-serif; background:#f6f6f6; margin:0; padding:0;}

.app-header {
  position:sticky; top:0; z-index:50;
  display:flex; align-items:center; justify-content:space-between; gap:6px;
  max-width:700px; margin:8px auto 0;
  padding:10px 14px;
  background:#800000;
  border-radius:14px;
  box-shadow:0 4px 14px rgba(0,0,0,.08);
}
.app-header h1 {
  flex:1 1 auto; min-width:0;
  margin:0; font-size:18px; color:#ffffff; font-weight:800;
  font-family:"Segoe UI", Arial, sans-serif;
  letter-spacing:.4px; text-align:center; pointer-events:none;
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
}
.header-user-badge {
  position:relative;
  flex:0 1 auto; min-width:0;
  display:flex; align-items:center; gap:4px;
  color:#ffffff; font-size:12px; font-weight:700;
  max-width:120px;
  cursor:default;
}
.header-user-badge .user-icon {font-size:14px; flex-shrink:0; line-height:1; transition:transform 150ms ease;}
.header-user-badge .user-name {
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap; min-width:0;
  transition:all 150ms ease;
}
/* Khi di chuột qua (desktop) hoặc chạm/nhấn giữ (mobile): tên user nổi to lên, đè lên trên,
   không đẩy layout xung quanh. Rời chuột / nhấc tay ra thì tự thu về như cũ. */
.header-user-badge:hover .user-name,
.header-user-badge:active .user-name {
  position:absolute;
  right:0; top:50%; transform:translateY(-50%) scale(1.25);
  transform-origin:right center;
  background:#2c2c2c;
  color:#fff;
  padding:5px 12px;
  border-radius:8px;
  white-space:nowrap;
  max-width:none;
  overflow:visible;
  box-shadow:0 6px 16px rgba(0,0,0,.3);
  z-index:80;
}
.header-user-badge:hover .user-icon,
.header-user-badge:active .user-icon {transform:scale(1.15);}
.hamburger-btn {
  width:auto; font-size:22px; line-height:1; flex-shrink:0;
  background:#fff; color:#7a0026; border:1px solid #e3d3cc;
  border-radius:10px; padding:8px 12px; margin:0;
  cursor:pointer; box-shadow:0 2px 8px rgba(0,0,0,.08);
  position:relative; z-index:2;
}
.hamburger-btn:hover, .hamburger-btn:active {background:#fff5f6;}
.hamburger-btn::after {
  content:"Menu";
  position:absolute; top:calc(100% + 8px); left:50%; transform:translateX(-50%) translateY(-4px);
  background:#2c2c2c; color:#fff; font-size:12px; font-weight:600;
  padding:4px 9px; border-radius:6px; white-space:nowrap;
  opacity:0; pointer-events:none; transition:opacity 150ms ease, transform 150ms ease;
  box-shadow:0 4px 10px rgba(0,0,0,.2);
}
.hamburger-btn:hover::after {opacity:1; transform:translateX(-50%) translateY(0);}
@media (hover:none) {
  .hamburger-btn::after {display:none;}
}
.hamburger-menu {
  position:absolute; top:68px; left:16px; right:16px;
  max-width:270px;
  max-height:calc(100vh - 84px);
  overflow-y:auto;
  background:#fff; border-radius:12px; box-shadow:0 10px 30px rgba(0,0,0,.18);
  padding:6px; z-index:60;
}
.menu-item {
  display:block; width:100%; text-align:left; text-decoration:none;
  background:none; border:none; border-radius:8px;
  padding:9px 10px; margin:1px 0; font-size:14.5px; line-height:1.3; color:#333; cursor:pointer;
}
.menu-item:hover {background:#f5eff0;}
.menu-item.danger {color:#c62828; font-weight:700;}
.menu-item.info {color:#1976d2; font-weight:700;}
.menu-divider {border:none; border-top:1px solid #eee; margin:4px 2px;}

.container {max-width:700px; margin:8px auto 12px; background:white; padding:14px; border-radius:12px; box-shadow:0 0 10px #aaa;}
h2 {margin-top:0;}
label {display:block; font-weight:600; margin-bottom:6px;}
select, input, button {font-size:16px; padding:10px; margin:4px 0; border-radius:8px;}
select, input[type="number"] {width:100%; border:2px solid #222;}
select {
  appearance:none; -webkit-appearance:none;
  background:#fff url("data:image/svg+xml;charset=UTF-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%237a0026' d='M12 16l-6-6h12z'/%3E%3C/svg%3E") no-repeat right 12px center;
  background-size:18px; padding-right:36px;
}
button {background:#800000; color:white; border:none; cursor:pointer; width:100%; font-weight:700;}
button:hover, button:active {background:#a00000;}
.form-group {margin:14px 0;}
.info-text {font-weight:700; color:#7a0026; margin:8px 0;}
.checkbox-row label {display:flex; align-items:center; gap:8px; font-weight:600; cursor:pointer; margin:0;}
.checkbox-row input[type="checkbox"] {width:18px; height:18px; margin:0;}
.time-input-group {background:#fff5f6; border-radius:10px; padding:12px 14px; margin:10px 0;}
.time-input-group .hint {font-size:12.5px; color:#6b6b6b; margin:8px 0 0; line-height:1.5;}
hr {border:none; border-top:1px solid #eee; margin:16px 0;}

.exam-status-bar {
  display:flex; align-items:center; justify-content:space-between; gap:10px;
  background:#fff5f6; color:#7a0026; font-weight:700; font-size:14px;
  padding:6px 12px; border-radius:8px; margin:-2px 0 8px; flex-shrink:0;
}
.exam-status-bar.warning {background:#c62828; color:#fff;}
.exam-topic-name {overflow:hidden; text-overflow:ellipsis; white-space:nowrap; text-align:left;}
.exam-timer {white-space:nowrap; flex-shrink:0;}

.question {background:#fafafa; padding:10px 12px; margin-bottom:8px; border-radius:8px; font-size:15px; line-height:1.4; word-wrap: break-word; flex-shrink:0;}
.option {display:block; margin:3px 0; padding:5px 6px; font-size:14.5px; line-height:1.35; word-wrap:break-word; border-radius:6px;}
.option input {width:auto; margin-right:6px;}
.correct-mark {color:green; font-weight:bold; margin-right:4px;}

#quizContainerWrapper {
  display:flex;
  flex-direction:column;
  height: calc(100vh - 110px);
  height: calc(100dvh - 110px);
  overflow:hidden;
}
#quiz-container {flex:1 1 auto; min-height:0; overflow-y:auto; -webkit-overflow-scrolling:touch;}
#quiz-container button {flex-shrink:0;}
.hidden {display:none !important;}
@media (max-width:480px){
  .container {margin:6px auto; padding:10px; border-radius:10px;}
  .app-header {margin:6px 6px 0; padding:8px 10px; gap:4px;}
  .app-header h1 {font-size:14.5px;}
  .header-user-badge {font-size:11px; max-width:78px;}
  .header-user-badge .user-icon {font-size:12.5px;}
  .hamburger-menu {left:8px; right:8px; top:58px;}
  .exam-status-bar {padding:5px 10px; font-size:12.5px; margin-bottom:6px; gap:6px;}
  .question {padding:8px 10px; margin-bottom:6px; font-size:14.5px;}
  .option {margin:2px 0; padding:4px 6px; font-size:14px;}
  #quiz-container button {padding:9px; font-size:15px; margin-top:6px;}
  #quizContainerWrapper {height: calc(100vh - 88px); height: calc(100dvh - 88px);}
}

.modal-overlay {
  position:fixed; inset:0; background:rgba(0,0,0,.5); z-index:200;
  display:flex; justify-content:center; align-items:flex-start;
  padding:16px; overflow-y:auto;
}
.modal-box {background:#fff; border-radius:14px; width:100%; max-width:700px; margin-top:16px; padding:18px; box-shadow:0 20px 60px rgba(0,0,0,.25);}
.modal-header {display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:10px;}
.modal-header h3 {margin:0; color:#7a0026;}
.modal-actions {display:flex; gap:8px; flex-wrap:wrap; margin-bottom:6px;}
.modal-actions button, .close-btn {width:auto; padding:9px 12px; font-size:14px; margin:0;}
.review-item {background:#fafafa; border-radius:8px; padding:12px; margin-bottom:10px;}
.review-q {font-weight:700; margin-bottom:8px;}
.review-status {font-weight:700;}
.review-status.ok {color:#0f6a4f;}
.review-status.bad {color:#c62828;}
.review-status.none {color:#888;}
.review-option {display:block; padding:4px 6px; border-radius:6px; margin:3px 0;}
.review-option.correct {color:#0f6a4f; font-weight:700;}
.review-option.wrong-selected {color:#c62828; font-weight:700;}
.review-summary {background:#fff5f6; border:1px solid #e3d3cc; border-radius:10px; padding:12px 14px; margin-bottom:14px; font-size:14.5px; line-height:1.8;}
.review-summary .stat-ok {color:#0f6a4f; font-weight:700;}
.review-summary .stat-bad {color:#c62828; font-weight:700;}
.review-summary .stat-none {color:#888; font-weight:700;}
.review-summary .time-row {display:block; margin-top:6px; padding-top:6px; border-top:1px dashed #e3d3cc; font-size:13.5px; color:#5a2d3b;}
</style>
</head>
<body>

<div class="app-header">
  <button id="hamburgerBtn" class="hamburger-btn" aria-label="Menu">☰</button>
  <h1>ÔN THI NGHIỆP VỤ</h1>
  <span id="headerUserBadge" class="header-user-badge hidden"><span class="user-icon">👤</span><span id="headerUserName" class="user-name"></span></span>
  <div id="hamburgerMenu" class="hamburger-menu hidden">
    <button id="submitEarlyBtn" class="menu-item danger hidden">🚩 Kết thúc giữa chừng (Nộp bài sớm)</button>
    <button id="viewResultsBtn" class="menu-item info hidden">📋 Xem đáp án đã thi</button>
    <hr class="menu-divider">
    <a class="menu-item" href="/change_password">🔑 Đổi mật khẩu</a>
    <a class="menu-item" href="/logout">🚪 Đăng xuất</a>
  </div>
</div>

<div class="container" id="setupContainer">
  <div class="form-group">
    <label for="fileSelect">Chọn bộ đề thi</label>
    <select id="fileSelect"><option disabled selected>--Chọn bộ đề--</option></select>
  </div>

  <p id="totalQuestionsText" class="info-text">Tổng số câu hỏi trong bộ đề: ...</p>

  <div class="form-group">
    <label for="numQuestions">Số câu chọn ôn</label>
    <input id="numQuestions" type="number" min="1" value="1">
  </div>

  <div class="form-group checkbox-row">
    <label><input type="checkbox" id="noRepeatCheckbox"> Không lặp câu đã thi (trong phiên đăng nhập)</label>
  </div>
  <p id="noRepeatInfoText" class="hint" style="margin:-6px 0 10px; color:#6b6b6b; font-size:12.5px; line-height:1.5;">Bật chế độ này: mỗi lần thi sẽ chọn các câu bạn <strong>chưa thi</strong> trong bộ đề này (kể từ lúc đăng nhập). Khi đã thi hết toàn bộ câu hỏi, hệ thống sẽ tự động bắt đầu lại vòng mới.</p>

  <div class="form-group checkbox-row">
    <label><input type="checkbox" id="useTimeCheckbox"> Chọn thời gian hoặc không</label>
  </div>

  <div id="timeInputGroup" class="time-input-group hidden">
    <label for="timeMinutes">Thời gian làm bài (phút)</label>
    <input id="timeMinutes" type="number" min="1" value="15">
    <p class="hint">Nếu chọn thời gian, hệ thống sẽ đếm ngược số phút bạn nhập. Hết giờ bài thi sẽ tự động nộp. Nếu không chọn, bạn làm bài không giới hạn thời gian.</p>
  </div>

  <hr>
  <button id="startBtn">▶ Bắt đầu thi</button>
</div>

<div class="container hidden" id="quizContainerWrapper">
  <div id="examStatusBar" class="exam-status-bar hidden">
    <span id="examTopicName" class="exam-topic-name">📘 ...</span>
    <span id="timerDisplay" class="exam-timer hidden">⏱ <span id="timerText">--:--</span></span>
  </div>
  <div id="quiz-container"></div>
</div>

<div id="resultsModalOverlay" class="modal-overlay hidden">
  <div class="modal-box">
    <div class="modal-header">
      <h3>📋 Kết quả đáp án đã thi</h3>
      <button id="closeModalBtn" class="close-btn" style="background:#616161;">✕ Đóng</button>
    </div>
    <div class="modal-actions">
      <button id="exportExcelBtn" style="background:#2e7d32;">📊 Xuất Excel</button>
      <button id="exportWordBtn" style="background:#1976d2;">📄 Xuất Word</button>
      <button id="printResultsBtn" style="background:#555;">🖨 In</button>
    </div>
    <hr>
    <div id="resultsModalBody"></div>
  </div>
</div>

<script>
const fileSelect = document.getElementById("fileSelect");
const totalText = document.getElementById("totalQuestionsText");
const numInput = document.getElementById("numQuestions");
const noRepeatCheckbox = document.getElementById("noRepeatCheckbox");
const useTimeCheckbox = document.getElementById("useTimeCheckbox");
const timeInputGroup = document.getElementById("timeInputGroup");
const timeMinutesInput = document.getElementById("timeMinutes");
const startBtn = document.getElementById("startBtn");
const setupContainer = document.getElementById("setupContainer");
const quizContainerWrapper = document.getElementById("quizContainerWrapper");
const quizContainer = document.getElementById("quiz-container");
const hamburgerBtn = document.getElementById("hamburgerBtn");
const hamburgerMenu = document.getElementById("hamburgerMenu");
const submitEarlyBtn = document.getElementById("submitEarlyBtn");
const viewResultsBtn = document.getElementById("viewResultsBtn");
const examStatusBar = document.getElementById("examStatusBar");
const examTopicName = document.getElementById("examTopicName");
const timerDisplay = document.getElementById("timerDisplay");
const timerText = document.getElementById("timerText");
const headerUserBadge = document.getElementById("headerUserBadge");
const headerUserName = document.getElementById("headerUserName");
const resultsModalOverlay = document.getElementById("resultsModalOverlay");
const resultsModalBody = document.getElementById("resultsModalBody");
const closeModalBtnEl = document.getElementById("closeModalBtn");

let quizData = [];
let currentIndex = 0;
let correctCount = 0;
let answeredCount = 0;
let timerInterval = null;
let remainingSeconds = 0;
let answersMap = {};
let reviewData = [];
let examStartTime = null;
let examEndTime = null;

async function showHeaderUserBadge(){
    try{
        const res = await fetch("/api/whoami");
        const data = await res.json();
        if(!data.email) return;
        const username = data.email.split("@")[0];
        if(!username) return;
        headerUserName.textContent = username;
        headerUserName.title = username;
        headerUserBadge.classList.remove("hidden");
    }catch(err){ }
}

async function refreshFileInfo(){
    if(!fileSelect.value) return;
    const res = await fetch("/get_info?file="+encodeURIComponent(fileSelect.value)+"&noRepeat="+(noRepeatCheckbox.checked?"1":"0"));
    const data = await res.json();
    numInput.max = data.total;
    if(noRepeatCheckbox.checked){
        totalText.textContent = `Tổng số: ${data.total} câu - Chưa thi: ${data.remaining} / Đã thi: ${data.total - data.remaining}`;
    } else {
        totalText.textContent = "Tổng số câu hỏi trong bộ đề: " + data.total;
    }
}

async function backToSetup(){
    stopTimer();
    hamburgerMenu.classList.add("hidden");
    submitEarlyBtn.classList.add("hidden");
    viewResultsBtn.classList.add("hidden");
    examStatusBar.classList.add("hidden");
    quizContainerWrapper.classList.add("hidden");
    setupContainer.classList.remove("hidden");
    await refreshFileInfo();
}

async function initQuiz(){
    showHeaderUserBadge();
    const resFiles = await fetch("/list_files");
    const files = await resFiles.json();
    if(files.length>0){
        fileSelect.innerHTML = '<option disabled selected>--Chọn bộ đề--</option>';
        files.forEach(f=>{
            const name=f.replace(/\.[^.]+$/,"");
            fileSelect.innerHTML += `<option value="${f}">${name}</option>`;
        });
    }else{
        fileSelect.innerHTML = '<option>Không có file</option>';
    }

    fileSelect.addEventListener("change", refreshFileInfo);
    noRepeatCheckbox.addEventListener("change", refreshFileInfo);

    useTimeCheckbox.addEventListener("change", ()=>{
        timeInputGroup.classList.toggle("hidden", !useTimeCheckbox.checked);
    });

    hamburgerBtn.onclick = (e)=>{
        e.stopPropagation();
        hamburgerMenu.classList.toggle("hidden");
    };
    hamburgerMenu.addEventListener("click", (e)=> e.stopPropagation());
    document.addEventListener("click", ()=> hamburgerMenu.classList.add("hidden"));

    submitEarlyBtn.onclick = ()=>{
        hamburgerMenu.classList.add("hidden");
        if(!confirm("Bạn có chắc muốn kết thúc bài thi giữa chừng? Hệ thống sẽ nộp bài với các câu đã trả lời.")) return;
        finishQuiz("early");
    };

    viewResultsBtn.onclick = ()=>{
        hamburgerMenu.classList.add("hidden");
        openResultsModal();
    };

    closeModalBtnEl.onclick = closeResultsModal;
    document.getElementById("exportExcelBtn").onclick = exportExcel;
    document.getElementById("exportWordBtn").onclick = exportWord;
    document.getElementById("printResultsBtn").onclick = printResults;
    resultsModalOverlay.addEventListener("click", (e)=>{
        if(e.target === resultsModalOverlay) closeResultsModal();
    });

    startBtn.onclick = async ()=>{
        if(!fileSelect.value){ alert("Chưa chọn bộ đề"); return; }
        const res = await fetch("/start_quiz", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({file:fileSelect.value, num:parseInt(numInput.value), noRepeat: noRepeatCheckbox.checked})});
        const data = await res.json();
        if(data.error){ alert(data.error); return; }
        quizData = data.questions || [];
        if(quizData.length===0){ alert("Không có câu hỏi hợp lệ, hoặc bạn đã thi hết câu hỏi khả dụng."); return; }

        if(noRepeatCheckbox.checked){
            if(data.poolReset){
                alert("Bạn đã thi hết toàn bộ câu hỏi của bộ đề này. Hệ thống bắt đầu một vòng ôn tập mới, các câu hỏi có thể lặp lại từ vòng trước.");
            } else if(data.partial){
                alert(`Bộ đề này chỉ còn ${quizData.length} câu chưa thi (ít hơn số bạn chọn), hệ thống đã lấy hết số câu còn lại. Lần thi tiếp theo sẽ tự động bắt đầu vòng ôn tập mới.`);
            }
        }

        currentIndex = 0;
        correctCount = 0;
        answeredCount = 0;
        answersMap = {};
        reviewData = [];
        examStartTime = new Date();
        examEndTime = null;

        setupContainer.classList.add("hidden");
        quizContainerWrapper.classList.remove("hidden");
        submitEarlyBtn.classList.remove("hidden");
        viewResultsBtn.classList.add("hidden");

        const selectedOption = fileSelect.options[fileSelect.selectedIndex];
        const topicLabel = selectedOption ? selectedOption.textContent : fileSelect.value;
        examTopicName.textContent = "📘 " + topicLabel;
        examStatusBar.classList.remove("hidden");
        examStatusBar.classList.remove("warning");
        timerDisplay.classList.add("hidden");

        if(useTimeCheckbox.checked){
            const minutes = parseInt(timeMinutesInput.value) || 0;
            if(minutes > 0){
                timerDisplay.classList.remove("hidden");
                startTimer(minutes * 60);
            }
        }

        showQuestion(currentIndex);
    };
}

function startTimer(seconds){
    remainingSeconds = seconds;
    updateTimerText();
    timerInterval = setInterval(()=>{
        remainingSeconds--;
        if(remainingSeconds <= 0){
            clearInterval(timerInterval);
            timerText.textContent = "00:00";
            finishQuiz("timeout");
            return;
        }
        updateTimerText();
        if(remainingSeconds <= 60) examStatusBar.classList.add("warning");
    }, 1000);
}

function updateTimerText(){
    const m = Math.floor(remainingSeconds / 60);
    const s = remainingSeconds % 60;
    timerText.textContent = String(m).padStart(2,"0") + ":" + String(s).padStart(2,"0");
}

function stopTimer(){
    if(timerInterval){ clearInterval(timerInterval); timerInterval = null; }
}

function showQuestion(i){
    const q = quizData[i];
    quizContainer.innerHTML = `<div class="question"><strong>Câu ${i+1}/${quizData.length}:</strong> ${q.question}</div>`;
    q.options.forEach(opt=>{
        const label=document.createElement("label");
        label.className="option";
        label.innerHTML=`<input type="radio" name="q${i}" value="${opt}"> ${opt}`;
        quizContainer.appendChild(label);
        label.querySelector("input").addEventListener("change", ()=>{
            const selected = label.querySelector("input");
            quizContainer.querySelectorAll("input[type=radio]").forEach(r=>r.disabled=true);
            answeredCount++;
            const isCorrect = selected.value === q.correctAnswer;
            answersMap[i] = {selected: selected.value, isCorrect: isCorrect};
            if(isCorrect) correctCount++;
            quizContainer.querySelectorAll(".option").forEach(optLabel=>{
                const inp = optLabel.querySelector("input");
                if(inp.value === q.correctAnswer){
                    optLabel.style.color = "green";
                    optLabel.style.fontWeight = "700";
                } else if(inp === selected){
                    optLabel.style.color = "red";
                }
            });
        });
    });
    const btn = document.createElement("button");
    btn.textContent = (i < quizData.length-1) ? "Tiếp tục" : "Nộp bài";
    btn.onclick = ()=>{
        const checked = quizContainer.querySelector("input:checked");
        if(!checked){ alert("Chọn đáp án"); return; }
        if(currentIndex < quizData.length-1){
            currentIndex++;
            showQuestion(currentIndex);
        } else {
            finishQuiz("completed");
        }
    };
    quizContainer.appendChild(btn);
}

function buildReviewData(){
    return quizData.map((q,i)=>{
        const rec = answersMap[i];
        return {
            index:i,
            question:q.question,
            options:q.options,
            correctAnswer:q.correctAnswer,
            selected: rec ? rec.selected : null,
            isCorrect: rec ? rec.isCorrect : false,
            answered: !!rec
        };
    });
}

function computeStats(){
    const total = reviewData.length;
    const correct = reviewData.filter(i=>i.isCorrect).length;
    const unanswered = reviewData.filter(i=>!i.answered).length;
    const wrong = total - correct - unanswered;
    return {total, correct, wrong, unanswered};
}

function pad2(n){ return String(n).padStart(2,"0"); }
function formatDateTime(d){
    if(!d) return "--";
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())} ${pad2(d.getDate())}/${pad2(d.getMonth()+1)}/${d.getFullYear()}`;
}
function formatDuration(ms){
    if(ms == null || ms < 0) return "--";
    const totalSec = Math.round(ms/1000);
    const h = Math.floor(totalSec/3600);
    const m = Math.floor((totalSec%3600)/60);
    const s = totalSec%60;
    let parts = [];
    if(h>0) parts.push(`${h} giờ`);
    if(m>0 || h>0) parts.push(`${m} phút`);
    parts.push(`${s} giây`);
    return parts.join(" ");
}

function statsHtml(){
    const s = computeStats();
    const durationMs = (examStartTime && examEndTime) ? (examEndTime - examStartTime) : null;
    return `<div class="review-summary">
        <strong>Tổng số câu:</strong> ${s.total}
        &nbsp;|&nbsp; <span class="stat-ok">✔ Đúng: ${s.correct}</span>
        &nbsp;|&nbsp; <span class="stat-bad">✘ Sai: ${s.wrong}</span>
        &nbsp;|&nbsp; <span class="stat-none">– Chưa trả lời: ${s.unanswered}</span>
        <span class="time-row">🕐 Bắt đầu: <strong>${formatDateTime(examStartTime)}</strong> &nbsp;|&nbsp; Kết thúc: <strong>${formatDateTime(examEndTime)}</strong> &nbsp;|&nbsp; Tổng thời gian: <strong>${formatDuration(durationMs)}</strong></span>
    </div>`;
}

function finishQuiz(mode){
    stopTimer();
    examEndTime = new Date();
    hamburgerMenu.classList.add("hidden");
    submitEarlyBtn.classList.add("hidden");
    timerDisplay.classList.add("hidden");
    examStatusBar.classList.remove("warning");

    reviewData = buildReviewData();
    viewResultsBtn.classList.remove("hidden");

    const unanswered = quizData.length - answeredCount;
    let title = "Hoàn thành bài thi!";
    if(mode === "timeout") title = "Đã hết thời gian làm bài!";
    if(mode === "early") title = "Bạn đã kết thúc bài thi giữa chừng.";

    let html = `<h3>${title}</h3><p>Kết quả: đúng <strong>${correctCount}/${quizData.length}</strong> câu.</p>`;
    if(unanswered > 0){
        html += `<p>Số câu chưa trả lời: ${unanswered}</p>`;
    }
    html += `<p style="color:#6b6b6b; font-size:14px;">🕐 ${formatDateTime(examStartTime)} → ${formatDateTime(examEndTime)} (${formatDuration(examEndTime - examStartTime)})</p>`;
    html += `<button id="viewResultsInlineBtn" style="background:#1976d2;">📋 Xem đáp án đã thi</button>`;
    html += `<button id="backToSetupBtn">⟲ Làm bộ đề khác</button>`;
    quizContainer.innerHTML = html;
    document.getElementById("backToSetupBtn").onclick = backToSetup;
    document.getElementById("viewResultsInlineBtn").onclick = openResultsModal;
}

function escapeHtml(str){
    return String(str).replace(/[&<>"']/g, s=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[s]));
}

function reviewToHtml(){
    let rows = "";
    reviewData.forEach(item=>{
        const optionsHtml = item.options.map(opt=>{
            let cls = "review-option";
            let mark = "";
            if(opt === item.correctAnswer){ cls += " correct"; mark = " ✔ (Đáp án đúng)"; }
            if(item.answered && opt === item.selected && opt !== item.correctAnswer){ cls += " wrong-selected"; mark = " ✘ (Bạn đã chọn)"; }
            return `<div class="${cls}">${escapeHtml(opt)}${mark}</div>`;
        }).join("");
        const statusCls = !item.answered ? "none" : (item.isCorrect ? "ok" : "bad");
        const statusText = !item.answered ? "Chưa trả lời" : (item.isCorrect ? "Đúng" : "Sai");
        rows += `<div class="review-item">
            <div class="review-q">Câu ${item.index+1}: ${escapeHtml(item.question)} — <span class="review-status ${statusCls}">${statusText}</span></div>
            ${optionsHtml}
        </div>`;
    });
    return rows;
}

function openResultsModal(){
    resultsModalBody.innerHTML = statsHtml() + reviewToHtml();
    resultsModalOverlay.classList.remove("hidden");
}
function closeResultsModal(){
    resultsModalOverlay.classList.add("hidden");
}

function downloadBlob(content, mime, filename){
    const blob = new Blob(["\ufeff", content], {type: mime});
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
}

function exportExcel(){
    const s = computeStats();
    const durationMs = (examStartTime && examEndTime) ? (examEndTime - examStartTime) : null;
    let table = `<table border="1" style="border-collapse:collapse;font-family:Arial;font-size:13px;margin-bottom:14px;">
        <tr><td colspan="2" style="background:#fff5f6;font-weight:700;">Tổng số câu</td><td>${s.total}</td></tr>
        <tr><td colspan="2" style="background:#e8f5e9;font-weight:700;color:#0f6a4f;">Số câu đúng</td><td>${s.correct}</td></tr>
        <tr><td colspan="2" style="background:#ffebee;font-weight:700;color:#c62828;">Số câu sai</td><td>${s.wrong}</td></tr>
        <tr><td colspan="2" style="background:#f5f5f5;font-weight:700;color:#888;">Chưa trả lời</td><td>${s.unanswered}</td></tr>
        <tr><td colspan="2" style="font-weight:700;">Thời gian bắt đầu</td><td>${formatDateTime(examStartTime)}</td></tr>
        <tr><td colspan="2" style="font-weight:700;">Thời gian kết thúc</td><td>${formatDateTime(examEndTime)}</td></tr>
        <tr><td colspan="2" style="font-weight:700;">Tổng thời gian thi</td><td>${formatDuration(durationMs)}</td></tr>
    </table>
    <table border="1" style="border-collapse:collapse;font-family:Arial;font-size:13px;">
        <tr style="background:#7a0026;color:#fff;">
            <th>STT</th><th>Câu hỏi</th><th>Đáp án đúng</th><th>Đáp án đã chọn</th><th>Kết quả</th>
        </tr>`;
    reviewData.forEach(item=>{
        const status = !item.answered ? "Chưa trả lời" : (item.isCorrect ? "Đúng" : "Sai");
        table += `<tr>
            <td>${item.index+1}</td>
            <td>${escapeHtml(item.question)}</td>
            <td>${escapeHtml(item.correctAnswer)}</td>
            <td>${item.answered ? escapeHtml(item.selected) : ""}</td>
            <td>${status}</td>
        </tr>`;
    });
    table += "</table>";
    const html = `<html><head><meta charset="UTF-8"></head><body>${table}</body></html>`;
    downloadBlob(html, "application/vnd.ms-excel", "ket_qua_thi.xls");
}

function exportWord(){
    const s = computeStats();
    const durationMs = (examStartTime && examEndTime) ? (examEndTime - examStartTime) : null;
    const summaryText = `<p><strong>Tổng số câu:</strong> ${s.total} &nbsp;|&nbsp; <strong>Đúng:</strong> ${s.correct} &nbsp;|&nbsp; <strong>Sai:</strong> ${s.wrong} &nbsp;|&nbsp; <strong>Chưa trả lời:</strong> ${s.unanswered}</p><p><strong>Bắt đầu:</strong> ${formatDateTime(examStartTime)} &nbsp;|&nbsp; <strong>Kết thúc:</strong> ${formatDateTime(examEndTime)} &nbsp;|&nbsp; <strong>Tổng thời gian:</strong> ${formatDuration(durationMs)}</p>`;
    const html = `<html><head><meta charset="UTF-8"></head><body><h2>Kết quả bài thi</h2>${summaryText}${reviewToHtml().replace(/class="[^"]*"/g,"")}</body></html>`;
    downloadBlob(html, "application/msword", "ket_qua_thi.doc");
}

function printResults(){
    const printWindow = window.open("", "_blank");
    if(!printWindow){ alert("Trình duyệt đã chặn cửa sổ in. Vui lòng cho phép popup để in."); return; }
    const style = `
        body{font-family:Arial;padding:20px;color:#222;}
        .review-item{background:#fafafa;border-radius:8px;padding:12px;margin-bottom:10px;}
        .review-q{font-weight:700;margin-bottom:8px;}
        .review-option{display:block;padding:4px 6px;margin:3px 0;}
        .review-option.correct{color:#0f6a4f;font-weight:700;}
        .review-option.wrong-selected{color:#c62828;font-weight:700;}
        .review-status.ok{color:#0f6a4f;}
        .review-status.bad{color:#c62828;}
        .review-status.none{color:#888;}
        .review-summary{background:#fff5f6;border:1px solid #e3d3cc;border-radius:10px;padding:12px 14px;margin-bottom:14px;}
        .review-summary .stat-ok{color:#0f6a4f;font-weight:700;}
        .review-summary .stat-bad{color:#c62828;font-weight:700;}
        .review-summary .stat-none{color:#888;font-weight:700;}
        .review-summary .time-row{display:block;margin-top:6px;padding-top:6px;border-top:1px dashed #e3d3cc;font-size:13.5px;color:#5a2d3b;}
    `;
    printWindow.document.write(`<html><head><meta charset="UTF-8"><title>Kết quả bài thi</title><style>${style}</style></head><body><h2>Kết quả bài thi</h2>${statsHtml()}${reviewToHtml()}</body></html>`);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(()=>{ printWindow.print(); }, 300);
}

initQuiz();
</script>
</body>
</html>
"""

@app.route("/quiz")
def quiz():
    device_id = request.cookies.get("device_id")
    email = request.cookies.get("email")
    df = load_devices()
    row = df[df["email"].astype(str).str.strip().str.lower() == (email or "")]
    if (
        not row.empty
        and str(row.iloc[0]["status"]).lower() == "approved"
        and not bool(row.iloc[0]["locked"])
        and not is_account_expired(row.iloc[0])
        and str(row.iloc[0]["active_device_id"] or "").strip() == (device_id or "")
    ):
        return render_template_string(HTML_QUIZ)
    return redirect("/")

HTML_CHANGE_PASSWORD = r"""
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1">
<title>Đổi mật khẩu</title>
<style>
* {box-sizing:border-box;}
body {font-family: Arial, sans-serif; background:#f6f6f6; margin:0; padding:0;}
.container {width:100%; max-width:500px; margin:24px auto; background:white; padding:22px; border-radius:16px; box-shadow:0 0 18px rgba(0,0,0,.12);}
h2 {margin-top:0; color:#7a0026;}
.form-group {margin-bottom:16px;}
label {display:block; margin-bottom:8px; font-weight:600;}
input {width:100%; padding:12px 14px; border:1px solid #ddd; border-radius:12px; font-size:16px;}
button {width:100%; padding:14px; border:none; border-radius:12px; background:#7a0026; color:white; font-weight:700; cursor:pointer; font-size:16px;}
button:hover {background:#5c001f;}
.message {min-height:22px; margin-top:14px; font-size:14px; word-break:break-word;}
.message.success {color:#0f6a4f;}
.message.error {color:#b91c1c;}
a.back-link {display:inline-block; margin-top:16px; color:#1976d2; text-decoration:none;}
a.back-link:hover {text-decoration:underline;}
@media (max-width:480px){
  .container {margin:12px; padding:16px;}
}
</style>
</head>
<body>
<div class="container">
  <h2>Đổi mật khẩu</h2>
  <div class="form-group">
    <label for="currentPassword">Mật khẩu hiện tại</label>
    <input type="password" id="currentPassword" placeholder="Nhập mật khẩu hiện tại">
  </div>
  <div class="form-group">
    <label for="newPassword">Mật khẩu mới</label>
    <input type="password" id="newPassword" placeholder="Nhập mật khẩu mới">
  </div>
  <div class="form-group">
    <label for="confirmPassword">Xác nhận mật khẩu mới</label>
    <input type="password" id="confirmPassword" placeholder="Nhập lại mật khẩu mới">
  </div>
  <button id="changePasswordBtn">Lưu mật khẩu mới</button>
  <p id="changeMsg" class="message"></p>
  <a class="back-link" href="/quiz">Quay lại trang thi</a>
</div>
<script>
function showMessage(el, text, type='error') {
  el.textContent = text;
  el.className = 'message ' + (type === 'success' ? 'success' : 'error');
}

async function handleChangePassword(){
  const currentPassword = document.getElementById('currentPassword').value.trim();
  const newPassword = document.getElementById('newPassword').value.trim();
  const confirmPassword = document.getElementById('confirmPassword').value.trim();
  const msg = document.getElementById('changeMsg');
  if(!currentPassword || !newPassword || !confirmPassword){
    showMessage(msg, 'Vui lòng điền đầy đủ các trường.');
    return;
  }
  if(newPassword !== confirmPassword){
    showMessage(msg, 'Mật khẩu mới và xác nhận không trùng khớp.');
    return;
  }
  if(newPassword.length < 6){
    showMessage(msg, 'Mật khẩu mới phải ít nhất 6 ký tự.');
    return;
  }
  const res = await fetch('/change_password', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({currentPassword, newPassword})});
  const data = await res.json();
  showMessage(msg, data.msg, data.success ? 'success' : 'error');
  if(data.success){
    document.getElementById('currentPassword').value = '';
    document.getElementById('newPassword').value = '';
    document.getElementById('confirmPassword').value = '';
  }
}

document.getElementById('changePasswordBtn').onclick = handleChangePassword;
</script>
</body>
</html>
"""

ADMIN_CHANGE_PASSWORD_HTML = r"""
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1">
<title>Đổi mật khẩu quản trị</title>
<style>
* {box-sizing:border-box;}
body {font-family: Arial, sans-serif; background:#f6f6f6; margin:0; padding:0;}
.container {width:100%; max-width:500px; margin:24px auto; background:white; padding:22px; border-radius:16px; box-shadow:0 0 18px rgba(0,0,0,.12);}
h2 {margin-top:0; color:#7a0026;}
.form-group {margin-bottom:16px;}
label {display:block; margin-bottom:8px; font-weight:600;}
input {width:100%; padding:12px 14px; border:1px solid #ddd; border-radius:12px; font-size:16px;}
button {width:100%; padding:14px; border:none; border-radius:12px; background:#7a0026; color:white; font-weight:700; cursor:pointer; font-size:16px;}
button:hover {background:#5c001f;}
.message {min-height:22px; margin-top:14px; font-size:14px; word-break:break-word;}
.message.success {color:#0f6a4f;}
.message.error {color:#b91c1c;}
a.back-link {display:inline-block; margin-top:16px; color:#1976d2; text-decoration:none;}
a.back-link:hover {text-decoration:underline;}
@media (max-width:480px){
  .container {margin:12px; padding:16px;}
}
</style>
</head>
<body>
<div class="container">
  <h2>Đổi mật khẩu quản trị</h2>
  <form method="post" action="/admin/change_password">
    <div class="form-group">
      <label for="currentPassword">Mật khẩu hiện tại</label>
      <input type="password" id="currentPassword" name="currentPassword" placeholder="Nhập mật khẩu hiện tại" required>
    </div>
    <div class="form-group">
      <label for="newPassword">Mật khẩu mới</label>
      <input type="password" id="newPassword" name="newPassword" placeholder="Tối thiểu 6 ký tự" required>
    </div>
    <div class="form-group">
      <label for="confirmPassword">Xác nhận mật khẩu mới</label>
      <input type="password" id="confirmPassword" name="confirmPassword" placeholder="Nhập lại mật khẩu mới" required>
    </div>
    <button type="submit">Lưu mật khẩu mới</button>
  </form>
  {% if error %}<p class="message error">{{ error }}</p>{% endif %}
  {% if success %}<p class="message success">{{ success }}</p>{% endif %}
  <a class="back-link" href="/admin?pwd={{ pwd }}">← Quay lại trang quản trị</a>
</div>
</body>
</html>
"""

ADMIN_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Quản trị đăng ký</title>
<style>
* {box-sizing:border-box;}
body {font-family: Arial, sans-serif; background:#f6f6f6; margin:0; padding:0; font-size:14px;}
.container {max-width:1100px; margin:16px auto; background:white; padding:16px; border-radius:12px; box-shadow:0 0 10px #aaa;}
h2 {margin-top:0; font-size:18px;}
.summary {display:flex; gap:8px; flex-wrap:wrap; margin:10px 0 14px;}
.summary div {background:#f5f5f5; padding:8px 10px; border-radius:8px; min-width:100px; flex:1 1 100px; font-size:12.5px; line-height:1.5;}
.summary div strong {font-size:13px;}
.table-scroll {width:100%; overflow-x:auto; -webkit-overflow-scrolling:touch;}
table {width:100%; min-width:720px; border-collapse:collapse; margin-top:12px;}
th, td {padding:6px 7px; border:1px solid #ddd; text-align:left; font-size:12.5px; vertical-align:top;}
th {font-size:12.5px; white-space:nowrap;}
button {padding:6px 9px; border:none; border-radius:6px; cursor:pointer; color:white; font-size:12.5px; white-space:nowrap;}
.approve {background:#2e7d32;}
.reject {background:#c62828;}
input[type="text"] {padding:5px; min-width:140px; font-size:12.5px;}
.bulk-bar {margin:12px 0; padding:8px; background:#f8f8f8; border-radius:8px; display:flex; gap:6px; flex-wrap:wrap; align-items:center;}
.excel-box {margin:12px 0; padding:12px; background:#eef6fc; border:1px solid #b6d4fe; border-radius:10px; display:flex; gap:10px; flex-wrap:wrap; align-items:center; justify-content:space-between; font-size:12.5px;}
.excel-box form {display:flex; gap:6px; align-items:center; flex-wrap:wrap;}
.excel-box input[type="file"] {font-size:12.5px; max-width:190px;}
.excel-btn-download {background:#1976d2; color:white; text-decoration:none; padding:6px 9px; border-radius:6px; font-weight:700; font-size:12.5px; display:inline-block; white-space:nowrap;}
.excel-btn-download:hover {background:#115293;}
.search-bar {margin:12px 0 4px; display:flex; gap:8px; align-items:center; flex-wrap:wrap;}
.search-bar input[type="search"] {flex:1; min-width:200px; padding:7px 9px; border:1px solid #ccc; border-radius:8px; font-size:13px;}
.search-bar input[type="search"]:focus {outline:none; border-color:#7a0026; box-shadow:0 0 0 3px rgba(122,0,38,.12);}
.search-count {font-size:12px; color:#666; white-space:nowrap;}
.no-results-row td {text-align:center; color:#888; padding:14px; font-style:italic;}
.expiry-status {font-weight:700; white-space:nowrap; display:block; margin-bottom:4px; font-size:12px;}
.expiry-status.ok {color:#2e7d32;}
.expiry-status.bad {color:#c62828;}
.expiry-status.none {color:#555;}
.expiry-form {display:flex; gap:3px; align-items:center; flex-wrap:wrap;}
.expiry-form input[type="number"] {width:44px; padding:4px; min-width:0; font-size:12px;}
.expiry-form select {padding:4px; font-size:11.5px;}
.expiry-form button {padding:4px 6px; font-size:11px;}
.admin-topbar {display:flex; align-items:center; justify-content:space-between; gap:10px; position:relative;}
.admin-topbar h2 {margin:0;}
.admin-hamburger-btn {
  width:auto; font-size:18px; line-height:1; flex-shrink:0;
  background:#fff; color:#7a0026; border:1px solid #e3d3cc;
  border-radius:9px; padding:6px 10px; margin:0;
  cursor:pointer; box-shadow:0 2px 6px rgba(0,0,0,.08);
}
.admin-hamburger-btn:hover, .admin-hamburger-btn:active {background:#fff5f6;}
.admin-hamburger-menu {
  position:absolute; top:40px; right:0; min-width:190px;
  background:#fff; border-radius:12px; box-shadow:0 10px 28px rgba(0,0,0,.18);
  padding:6px; z-index:60;
}
.admin-menu-item {
  display:block; width:100%; text-align:left; text-decoration:none;
  background:none; border:none; border-radius:8px;
  padding:8px 9px; margin:1px 0; font-size:13px; color:#333; cursor:pointer;
}
.admin-menu-item:hover {background:#f5eff0;}
.admin-menu-item.danger {color:#c62828; font-weight:700;}
.hidden {display:none !important;}
.alert-msg {padding:8px 12px; border-radius:8px; font-weight:700; margin:8px 0; font-size:13px;}
.alert-success {background:#e8f5e9; color:#2e7d32; border:1px solid #a5d6a7;}
.alert-error {background:#ffebee; color:#c62828; border:1px solid #ef9a9a;}
.action-cell {display:inline-flex; gap:4px; align-items:center; flex-wrap:nowrap; white-space:nowrap;}
.action-cell button {min-width:0;}
.pw-cell {display:flex; align-items:center; gap:4px; flex-wrap:nowrap; white-space:nowrap;}
@media (max-width:480px){
  .container {margin:8px; padding:10px; border-radius:10px;}
}
</style>
</head>
<body>
<div class="container">
<div class="admin-topbar">
  <h2>Quản lý đăng ký</h2>
  <button id="adminHamburgerBtn" class="admin-hamburger-btn" aria-label="Menu">☰</button>
  <div id="adminHamburgerMenu" class="admin-hamburger-menu hidden">
    <a class="admin-menu-item" href="/admin/change_password">🔑 Đổi mật khẩu</a>
    <a class="admin-menu-item danger" href="/admin/logout">🚪 Thoát</a>
  </div>
</div>

{% if msg %}<div class="alert-msg alert-success">{{ msg }}</div>{% endif %}
{% if error %}<div class="alert-msg alert-error">{{ error }}</div>{% endif %}

<div class="summary">
<div><strong>Chờ duyệt</strong><br>{{ stats.pending }}</div>
<div><strong>Đã duyệt</strong><br>{{ stats.approved }}</div>
<div><strong>Từ chối</strong><br>{{ stats.rejected }}</div>
<div><strong>Tổng</strong><br>{{ stats.total }}</div>
</div>

<div class="excel-box">
  <div>
    <strong>📊 Thêm User từ Excel:</strong>
    <a href="/admin/download_user_template" class="excel-btn-download">📥 Tải mẫu</a>
  </div>
  <form method="post" action="/admin/upload_users" enctype="multipart/form-data">
    <input type="hidden" name="pwd" value="{{ pwd }}">
    <input type="file" name="excel_file" accept=".xlsx, .xls" required>
    <button type="submit" style="background:#2e7d32;" onclick="return confirm('Tải lên và duyệt tự động các tài khoản trong file Excel này?')">📤 Upload</button>
  </form>
</div>

<form id="bulkForm" method="post" action="/admin/bulk" class="bulk-bar">
<input type="hidden" name="pwd" value="{{ pwd }}">
<div id="bulkSelectedEmails"></div>
<button class="approve" type="button" onclick="submitBulkAction('approve')">Duyệt hàng loạt</button>
<button class="reject" type="button" onclick="submitBulkAction('reject')">Từ chối hàng loạt</button>
</form>
<div class="search-bar">
<input type="search" id="adminSearchInput" placeholder="🔍 Tìm theo email..." oninput="filterAdminTable()" autocomplete="off">
<span id="searchResultCount" class="search-count"></span>
</div>
<div class="table-scroll">
<table id="adminTable">
<tr><th><input type="checkbox" id="checkAll"></th><th>Email</th><th>Trạng thái</th><th>Hạn sử dụng</th><th>Mật khẩu</th><th>Ngày đăng ký</th><th>Hành động</th></tr>
{% for row in rows %}
<tr data-email="{{ row.email }}">
<td><input type="checkbox" class="rowCheck" name="selected_emails" value="{{ row.email }}"></td>
<td>{{ row.email }}</td>
<td>{{ row.status }}</td>
<td style="min-width:170px;">
  {% if row.expires_at %}
    {% if is_expired(row.expires_at) %}
      <span class="expiry-status bad">⛔ {{ row.expires_at[:10] }}</span>
    {% else %}
      <span class="expiry-status ok">✅ {{ row.expires_at[:10] }}</span>
    {% endif %}
  {% else %}
    <span class="expiry-status none">♾ Không giới hạn</span>
  {% endif %}
  <form method="post" action="/admin/set_expiry" class="expiry-form">
    <input type="hidden" name="pwd" value="{{ pwd }}">
    <input type="hidden" name="email" value="{{ row.email }}">
    <input type="number" name="expiry_value" min="1" value="1">
    <select name="expiry_unit">
      <option value="day">Ngày</option>
      <option value="month">Tháng</option>
    </select>
    <button type="submit" name="expiry_action" value="set" style="background:#1976d2;" onclick="return confirm('Đặt hạn sử dụng mới cho tài khoản này?')">Đặt</button>
    <button type="submit" name="expiry_action" value="clear" style="background:#616161;" onclick="return confirm('Bỏ giới hạn (cho phép dùng không thời hạn)?')">Bỏ hạn</button>
  </form>
</td>
<td>
  {% if row.raw_password %}
  <div class="pw-cell">
    <span id="pw-{{ loop.index }}">{{ row.raw_password }}</span>
    <button type="button" onclick="copyPassword({{ loop.index }})" style="background:#1976d2;">Copy</button>
  </div>
  {% else %}
    —
  {% endif %}
</td>
<td style="white-space:nowrap;">{{ row.created_at or '' }}</td>
<td>
<form method="post" action="/admin/decision" class="action-cell">
<input type="hidden" name="pwd" value="{{ pwd }}">
<input type="hidden" name="email" value="{{ row.email }}">
{% if row.status|lower != 'approved' %}
<button class="approve" type="submit" name="action" value="approve" onclick="return confirm('Bạn có chắc muốn duyệt tài khoản này?')">Duyệt</button>
{% else %}
<span style="color:#2e7d32; font-weight:700; font-size:12px;">Đã duyệt</span>
{% endif %}
<button class="reject" type="submit" name="action" value="reject" onclick="return confirm('Bạn có chắc muốn từ chối tài khoản này?')">Từ chối</button>
<button type="submit" formaction="/admin/delete" formmethod="post" style="background:#616161;" onclick="return confirm('Bạn có chắc muốn xóa tài khoản này?')">Xóa</button>
</form>
</td>
</tr>
{% endfor %}
</table>
</div>
</div>
<script>
const adminHamburgerBtn = document.getElementById('adminHamburgerBtn');
const adminHamburgerMenu = document.getElementById('adminHamburgerMenu');
adminHamburgerBtn.onclick = (e)=>{
  e.stopPropagation();
  adminHamburgerMenu.classList.toggle('hidden');
};
adminHamburgerMenu.addEventListener('click', (e)=> e.stopPropagation());
document.addEventListener('click', ()=> adminHamburgerMenu.classList.add('hidden'));

document.getElementById('checkAll')?.addEventListener('change', function(){
  document.querySelectorAll('#adminTable tr[data-email]').forEach(tr=>{
    if(tr.style.display !== 'none'){
      const cb = tr.querySelector('.rowCheck');
      if(cb) cb.checked = this.checked;
    }
  });
});

function filterAdminTable(){
  const term = document.getElementById('adminSearchInput').value.trim().toLowerCase();
  const rows = document.querySelectorAll('#adminTable tr[data-email]');
  let visibleCount = 0;
  rows.forEach(tr=>{
    const email = (tr.getAttribute('data-email') || '').toLowerCase();
    const match = email.includes(term);
    tr.style.display = match ? '' : 'none';
    if(match) visibleCount++;
  });
  const countEl = document.getElementById('searchResultCount');
  countEl.textContent = term ? `Tìm thấy ${visibleCount} / ${rows.length} tài khoản` : '';
  const checkAll = document.getElementById('checkAll');
  if(checkAll) checkAll.checked = false;
}

function submitBulkAction(action){
  const selected = Array.from(document.querySelectorAll('.rowCheck:checked')).map(cb => cb.value);
  if(selected.length === 0){
    alert('Vui lòng chọn ít nhất một tài khoản.');
    return;
  }
  const confirmMessage = action === 'approve'
    ? `Bạn có chắc muốn duyệt ${selected.length} tài khoản?`
    : `Bạn có chắc muốn từ chối ${selected.length} tài khoản?`;
  if(!confirm(confirmMessage)){
    return;
  }
  const container = document.getElementById('bulkSelectedEmails');
  container.innerHTML = '';
  selected.forEach(email => {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'selected_emails';
    input.value = email;
    container.appendChild(input);
  });
  let actionInput = document.querySelector('#bulkForm input[name="action"]');
  if(!actionInput){
    actionInput = document.createElement('input');
    actionInput.type = 'hidden';
    actionInput.name = 'action';
    document.getElementById('bulkForm').appendChild(actionInput);
  }
  actionInput.value = action;
  document.getElementById('bulkForm').submit();
}

function copyPassword(index){
  const el = document.getElementById('pw-' + index);
  if(!el) return;
  const text = el.textContent.trim();

  const tryCopy = async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        alert('Mật khẩu đã sao chép.');
        return;
      }
    } catch (err) {}

    const temp = document.createElement('textarea');
    temp.value = text;
    temp.setAttribute('readonly', '');
    temp.style.position = 'fixed';
    temp.style.left = '-9999px';
    document.body.appendChild(temp);
    temp.select();
    try {
      document.execCommand('copy');
      alert('Mật khẩu đã sao chép.');
    } catch (err) {
      alert('Không thể sao chép tự động. Vui lòng sao chép thủ công.');
    } finally {
      document.body.removeChild(temp);
    }
  };

  tryCopy();
}
</script>
</body>
</html>
"""

@app.route("/admin")
def admin():
  if not is_admin_request():
    return render_template_string(ADMIN_LOGIN_HTML, error=request.args.get('error',''))

  df = load_devices()
  rows = df.to_dict(orient="records")
  stats = {
        "pending": int((df["status"].astype(str).str.lower() == "pending").sum()),
        "approved": int((df["status"].astype(str).str.lower() == "approved").sum()),
        "rejected": int((df["status"].astype(str).str.lower() == "rejected").sum()),
        "total": len(df)
    }
  return render_template_string(
    ADMIN_HTML,
    rows=rows,
    stats=stats,
    is_expired=is_expired_str,
    msg=request.args.get("msg", ""),
    error=request.args.get("error", ""),
    pwd=ADMIN_PASSWORD
)


def is_admin_request():
  return request.cookies.get("admin_auth") == "1" or request.args.get("pwd", "") == ADMIN_PASSWORD


@app.route('/admin/logout')
def admin_logout():
  resp = make_response(redirect('/'))
  resp.delete_cookie('admin_auth')
  return resp


@app.route('/admin/change_password', methods=["GET", "POST"])
def admin_change_password():
  global ADMIN_PASSWORD
  if not is_admin_request():
    return redirect("/admin")

  error = ""
  success = ""
  if request.method == "POST":
    current = (request.form.get("currentPassword") or "").strip()
    new_password = (request.form.get("newPassword") or "").strip()
    confirm_password = (request.form.get("confirmPassword") or "").strip()
    if current != ADMIN_PASSWORD:
      error = "Mật khẩu hiện tại không đúng."
    elif len(new_password) < 6:
      error = "Mật khẩu mới phải ít nhất 6 ký tự."
    elif new_password != confirm_password:
      error = "Mật khẩu mới và xác nhận không khớp."
    else:
      ADMIN_PASSWORD = new_password
      save_admin_password(new_password)
      success = "Đổi mật khẩu quản trị thành công. Hãy dùng mật khẩu mới cho lần đăng nhập sau."

  return render_template_string(ADMIN_CHANGE_PASSWORD_HTML, error=error, success=success, pwd=ADMIN_PASSWORD)


def load_devices():
    columns = ["email", "device_id", "active_device_id", "status", "activation_code", "password", "raw_password", "locked", "created_at", "updated_at", "note", "expires_at"]
    engine = _get_db_engine()
    loaded_from_db = False

    if engine is not None:
        try:
            df = pd.read_sql("SELECT * FROM devices", engine)
            loaded_from_db = True
        except Exception:
            pass

    if not loaded_from_db:
        if not os.path.exists(DEVICES_FILE):
            df = pd.DataFrame(columns=columns)
            save_devices(df)
            return df

        try:
            with open(DEVICES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = []

        if isinstance(data, dict):
            data = data.get("users", [])
        if not isinstance(data, list):
            data = []

        df = pd.DataFrame(data, columns=columns)

    for col in columns:
        if col not in df.columns:
            df[col] = ""
    df["email"] = df["email"].fillna("").astype(str)
    df["device_id"] = df["device_id"].fillna("").astype(str)
    df["active_device_id"] = df["active_device_id"].fillna("").astype(str)
    df["status"] = df["status"].fillna("pending").astype(str)
    df["activation_code"] = df["activation_code"].fillna("").astype(str)
    df["password"] = df["password"].fillna("").astype(str)
    df["raw_password"] = df["raw_password"].fillna("").astype(str)
    df["created_at"] = df["created_at"].fillna("").astype(str)
    df["updated_at"] = df["updated_at"].fillna("").astype(str)
    df["note"] = df["note"].fillna("").astype(str)
    df["locked"] = df["locked"].fillna(False).astype(bool)
    df["expires_at"] = df["expires_at"].fillna("").astype(str)
    df = df[columns]
    return df


def save_devices(df):
    columns = ["email", "device_id", "active_device_id", "status", "activation_code", "password", "raw_password", "locked", "created_at", "updated_at", "note", "expires_at"]
    df = df.copy()
    for col in columns:
        if col not in df.columns:
            df[col] = ""
    df = df[columns]
    df["email"] = df["email"].fillna("").astype(str)
    df["device_id"] = df["device_id"].fillna("").astype(str)
    df["active_device_id"] = df["active_device_id"].fillna("").astype(str)
    df["status"] = df["status"].fillna("pending").astype(str)
    df["activation_code"] = df["activation_code"].fillna("").astype(str)
    df["password"] = df["password"].fillna("").astype(str)
    df["created_at"] = df["created_at"].fillna("").astype(str)
    df["updated_at"] = df["updated_at"].fillna("").astype(str)
    df["note"] = df["note"].fillna("").astype(str)
    df["locked"] = df["locked"].fillna(False).astype(bool)
    df["expires_at"] = df["expires_at"].fillna("").astype(str)

    engine = _get_db_engine()
    if engine is not None:
        try:
            df.to_sql("devices", engine, if_exists="replace", index=False)
            return
        except Exception:
            pass

    with open(DEVICES_FILE, "w", encoding="utf-8") as f:
        json.dump(df.to_dict(orient="records"), f, ensure_ascii=False, indent=2)


def add_months(source_date, months):
    month_index = source_date.month - 1 + months
    year = source_date.year + month_index // 12
    month = month_index % 12 + 1
    day = min(source_date.day, calendar.monthrange(year, month)[1])
    return source_date.replace(year=year, month=month, day=day)


def now_vn():
    """Trả về thời gian hiện tại theo giờ Việt Nam (UTC+7).
    Dùng thay cho datetime.now() để không bị lệch giờ khi server host ở múi giờ khác (thường là UTC)."""
    from datetime import timezone
    return datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=7)


def is_expired_str(expires_at):
    expires_at = str(expires_at or "").strip()
    if not expires_at:
        return False
    try:
        exp_dt = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return False
    return now_vn() > exp_dt


def is_account_expired(row):
    return is_expired_str(row.get("expires_at", ""))


def generate_code(length=8):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+"
    return "".join(random.choices(chars, k=length))


def hash_password(password):
    return generate_password_hash(password)


def verify_password(password, stored_hash):
    stored_hash = str(stored_hash or "")
    if not stored_hash:
        return False
    if stored_hash.startswith("pbkdf2:") or stored_hash.startswith("scrypt:"):
        try:
            return check_password_hash(stored_hash, password)
        except Exception:
            return False
    return stored_hash == hashlib.sha256(password.encode("utf-8")).hexdigest()


def generate_password(length=6):
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=length))


DEFAULT_FIRST_PASSWORD = "cn3500@"


def send_approval_email(email, password="", note=""):
    if not MAIL_USERNAME or not MAIL_PASSWORD or not email:
        return {"success": False, "msg": "Chưa cấu hình SMTP. Mail không thể được gửi."}
    try:
        msg = EmailMessage()
        msg["Subject"] = "Tài khoản của bạn đã được phê duyệt"
        msg["From"] = MAIL_FROM or MAIL_USERNAME
        msg["To"] = email
        msg.set_content(
            f"Xin chào,\n\nTài khoản đăng ký {email} của bạn đã được admin phê duyệt."
            + (f"\nGhi chú: {note}" if note else "")
            + (f"\nMật khẩu đăng nhập của bạn là: {password}" if password else "")
            + "\n\nVui lòng dùng email và mật khẩu này để đăng nhập." 
        )
        if MAIL_USE_TLS:
            with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as smtp:
                smtp.starttls()
                smtp.login(MAIL_USERNAME, MAIL_PASSWORD)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as smtp:
                smtp.login(MAIL_USERNAME, MAIL_PASSWORD)
                smtp.send_message(msg)
        return {"success": True, "msg": "Email đã được gửi."}
    except Exception as e:
        return {"success": False, "msg": f"Không gửi được email: {e}"}


@app.route("/")
def index():
    return render_template_string(HTML_LOGIN)


VALID_EMAIL_RE = re.compile(r"^\S+@(agribank\.com\.vn|gmail\.com)$")


def is_valid_register_email(email):
    return bool(VALID_EMAIL_RE.match(email))


@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "msg": "Vui lòng nhập email"})
    if not is_valid_register_email(email):
        return jsonify({"success": False, "msg": "Email không hợp lệ. Chỉ chấp nhận email @agribank.com.vn hoặc @gmail.com."})

    df = load_devices()
    existing = df[df["email"].astype(str).str.strip().str.lower() == email]
    if not existing.empty:
        status = str(existing.iloc[0]["status"]).lower()
        if status == "approved":
            return jsonify({"success": False, "msg": "Email này đã được duyệt. Bạn có thể đăng nhập."})
        if status == "pending":
            return jsonify({"success": False, "msg": "Yêu cầu đăng ký của email này đang chờ xét duyệt."})
        if status == "rejected":
            df.loc[existing.index[0], "status"] = "pending"
            df.loc[existing.index[0], "locked"] = False
            save_devices(df)
            return jsonify({"success": True, "msg": "Yêu cầu đăng ký đã được gửi lại và đang chờ xét duyệt."})

    now = now_vn().strftime("%Y-%m-%d %H:%M:%S")
    new_row = pd.DataFrame([{"email": email, "device_id": str(uuid.uuid4()), "active_device_id": "", "status": "pending", "activation_code": "", "password": "", "raw_password": "", "locked": False, "created_at": now, "updated_at": now, "note": "Đăng ký mới"}])
    df = pd.concat([df, new_row], ignore_index=True)
    save_devices(df)
    return jsonify({"success": True, "msg": "Đăng ký thành công. Vui lòng chờ admin xét duyệt."})


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    if not email:
        return jsonify({"success": False, "msg": "Vui lòng nhập email"})
    if not password:
        return jsonify({"success": False, "msg": "Vui lòng nhập mật khẩu"})

    rl_key = f"{request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()}:{email}"
    if is_login_rate_limited(rl_key):
        return jsonify({"success": False, "msg": "Bạn đã nhập sai quá nhiều lần. Vui lòng thử lại sau ít phút."})

    try:
        if email in ADMIN_EMAILS:
            if password != ADMIN_PASSWORD:
                record_failed_login(rl_key)
                return jsonify({"success": False, "msg": "Email hoặc mật khẩu không đúng."})
            clear_failed_login(rl_key)
            current_device_id = str(uuid.uuid4())
            resp = make_response(jsonify({"success": True, "msg": "Đăng nhập quản trị thành công.", "admin": True}))
            set_app_cookie(resp, "admin_auth", "1", 24 * 3600)
            set_app_cookie(resp, "email", email, 365 * 24 * 3600)
            set_app_cookie(resp, "device_id", current_device_id, 365 * 24 * 3600)
            return resp
    except Exception:
        pass

    df = load_devices()
    row = df[df["email"].astype(str).str.strip().str.lower() == email]
    if row.empty:
        return jsonify({"success": False, "msg": "Email chưa đăng ký. Vui lòng thực hiện đăng ký trước."})

    status = str(row.iloc[0]["status"]).lower()
    if status == "pending":
        return jsonify({"success": False, "msg": "Email của bạn chưa được xét duyệt. Vui lòng chờ admin duyệt."})
    if status == "rejected":
        return jsonify({"success": False, "msg": "Email của bạn không được phê duyệt. Vui lòng liên hệ admin."})
    if bool(row.iloc[0]["locked"]):
        return jsonify({"success": False, "msg": "Tài khoản của bạn đã bị khóa."})
    if is_account_expired(row.iloc[0]):
        return jsonify({"success": False, "msg": f"Tài khoản của bạn đã hết hạn sử dụng (hết hạn: {str(row.iloc[0]['expires_at'])[:10]}). Vui lòng liên hệ admin để gia hạn."})
    stored_password = str(row.iloc[0]["password"] or "").strip()
    if not stored_password:
        return jsonify({"success": False, "msg": "Mật khẩu chưa được cấp. Vui lòng liên hệ admin."})
    if not verify_password(password, stored_password):
        record_failed_login(rl_key)
        return jsonify({"success": False, "msg": "Email hoặc mật khẩu không đúng."})
    clear_failed_login(rl_key)
    if not (stored_password.startswith("pbkdf2:") or stored_password.startswith("scrypt:")):
        df.at[row.index[0], "password"] = hash_password(password)

    current_device_id = (request.cookies.get("device_id") or "").strip()
    if not current_device_id:
        current_device_id = str(uuid.uuid4())

    active_device_id = str(row.iloc[0]["active_device_id"] or "").strip()
    if active_device_id and active_device_id != current_device_id:
        return jsonify({
            "success": False,
            "msg": "Tài khoản này đang đăng nhập trên thiết bị khác. Nếu bạn đã đăng xuất trên thiết bị cũ, nhấn 'Xóa đăng nhập cũ' để giải phóng phiên.",
            "otherDevice": True
        })

    now = now_vn().strftime("%Y-%m-%d %H:%M:%S")
    df.at[row.index[0], "device_id"] = current_device_id
    df.at[row.index[0], "active_device_id"] = current_device_id
    df.at[row.index[0], "updated_at"] = now
    save_devices(df)

    resp = make_response(jsonify({"success": True, "msg": "Đăng nhập thành công"}))
    set_app_cookie(resp, "device_id", current_device_id, 365 * 24 * 3600)
    set_app_cookie(resp, "email", email, 365 * 24 * 3600)
    return resp


@app.route("/api/whoami")
def api_whoami():
    email = (request.cookies.get("email") or "").strip()
    if not email:
        return jsonify({"email": None})
    return jsonify({"email": email})


@app.route("/logout")
def logout():
    device_id = request.cookies.get("device_id")
    email = request.cookies.get("email")
    if device_id and email:
        df = load_devices()
        row = df[df["email"].astype(str).str.strip().str.lower() == (email or "")]
        if not row.empty and str(row.iloc[0]["active_device_id"] or "").strip() == device_id:
            df.at[row.index[0], "active_device_id"] = ""
            df.at[row.index[0], "updated_at"] = now_vn().strftime("%Y-%m-%d %H:%M:%S")
            save_devices(df)
    if email:
        SESSION_USED_QUESTIONS.pop(email.strip().lower(), None)
        save_used_questions()
    resp = make_response(redirect("/"))
    resp.delete_cookie("device_id")
    resp.delete_cookie("email")
    return resp

@app.route("/change_password")
def change_password_page():
    device_id = request.cookies.get("device_id")
    email = request.cookies.get("email")
    if not email or not device_id:
        return redirect("/")
    df = load_devices()
    row = df[df["email"].astype(str).str.strip().str.lower() == (email or "")]
    if row.empty:
        return redirect("/")
    row = row.iloc[0]
    if str(row["status"]).lower() != "approved" or bool(row["locked"]) or is_account_expired(row) or str(row["active_device_id"] or "").strip() != device_id:
        return redirect("/")
    return render_template_string(HTML_CHANGE_PASSWORD)

@app.route("/change_password", methods=["POST"])
def change_password_action():
    data = request.json or {}
    current_password = (data.get("currentPassword") or "").strip()
    new_password = (data.get("newPassword") or "").strip()
    device_id = request.cookies.get("device_id")
    email = request.cookies.get("email")
    if not email or not device_id:
        return jsonify({"success": False, "msg": "Phiên đăng nhập không hợp lệ. Vui lòng đăng nhập lại."})
    if not current_password or not new_password:
        return jsonify({"success": False, "msg": "Vui lòng điền đầy đủ thông tin."})
    if len(new_password) < 6:
        return jsonify({"success": False, "msg": "Mật khẩu mới phải ít nhất 6 ký tự."})
    df = load_devices()
    row = df[df["email"].astype(str).str.strip().str.lower() == email]
    if row.empty:
        return jsonify({"success": False, "msg": "Email không tồn tại."})
    idx = row.index[0]
    row = row.iloc[0]
    if str(row["status"]).lower() != "approved" or bool(row["locked"]) or is_account_expired(row):
        return jsonify({"success": False, "msg": "Tài khoản không được phép đổi mật khẩu."})
    if str(row["active_device_id"] or "").strip() != device_id:
        return jsonify({"success": False, "msg": "Phiên đăng nhập không hợp lệ. Vui lòng đăng nhập lại."})
    if not verify_password(current_password, row["password"]):
        return jsonify({"success": False, "msg": "Mật khẩu hiện tại không đúng."})
    df.at[idx, "password"] = hash_password(new_password)
    df.at[idx, "raw_password"] = new_password
    df.at[idx, "updated_at"] = now_vn().strftime("%Y-%m-%d %H:%M:%S")
    save_devices(df)
    return jsonify({"success": True, "msg": "Đổi mật khẩu thành công."})

@app.route("/clear_session", methods=["POST"])
def clear_session():
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "msg": "Vui lòng nhập email để xóa phiên."})
    df = load_devices()
    row = df[df["email"].astype(str).str.strip().str.lower() == email]
    if row.empty:
        return jsonify({"success": False, "msg": "Email không tồn tại."})
    idx = row.index[0]
    active_device_id = str(row.iloc[0]["active_device_id"] or "").strip()
    if not active_device_id:
        return jsonify({"success": False, "msg": "Không có thiết bị cũ đang đăng nhập."})
    df.at[idx, "active_device_id"] = ""
    df.at[idx, "updated_at"] = now_vn().strftime("%Y-%m-%d %H:%M:%S")
    save_devices(df)
    resp = make_response(jsonify({"success": True, "msg": "Phiên đăng nhập cũ đã được xóa. Bạn có thể đăng nhập lại."}))
    resp.delete_cookie("device_id")
    resp.delete_cookie("email")
    return resp


@app.route("/admin/download_user_template")
def admin_download_user_template():
    if not is_admin_request():
        return "Không có quyền"
    
    sample_data = [
        {
            "Email": "nguyenvana@agribank.com.vn",
            "MatKhau": "cn3500@",
            "GhiChu": "Phòng Kế toán",
            "HanSuDungNgay": 365
        },
        {
            "Email": "tranvanb@gmail.com",
            "MatKhau": "123456",
            "GhiChu": "Phòng Tín dụng",
            "HanSuDungNgay": 180
        }
    ]
    df = pd.DataFrame(sample_data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="DanhSachUser")
    output.seek(0)
    
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    resp.headers["Content-Disposition"] = "attachment; filename=mau_dang_ky_user.xlsx"
    return resp


@app.route("/admin/upload_users", methods=["POST"])
def admin_upload_users():
    if not is_admin_request():
        return "Không có quyền"
    
    file = request.files.get("excel_file")
    if not file or not file.filename:
        return redirect(f"/admin?pwd={ADMIN_PASSWORD}&error=" + urllib.parse.quote("Chưa chọn file Excel."))
    
    try:
        df_upload = pd.read_excel(file)
    except Exception as e:
        return redirect(f"/admin?pwd={ADMIN_PASSWORD}&error=" + urllib.parse.quote(f"Không thể đọc file Excel: {e}"))
    
    df = load_devices()
    now = now_vn()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    
    added_count = 0
    skipped_count = 0
    
    col_map = {}
    for col in df_upload.columns:
        c_clean = re.sub(r'[^a-zA-Z]', '', str(col)).lower()
        if 'email' in c_clean:
            col_map['email'] = col
        elif 'khau' in c_clean or 'pass' in c_clean:
            col_map['password'] = col
        elif 'chu' in c_clean or 'note' in c_clean:
            col_map['note'] = col
        elif 'han' in c_clean or 'ngay' in c_clean or 'expiry' in c_clean:
            col_map['expiry'] = col

    email_col = col_map.get('email', df_upload.columns[0] if len(df_upload.columns) > 0 else None)
    if not email_col:
        return redirect(f"/admin?pwd={ADMIN_PASSWORD}&error=" + urllib.parse.quote("File Excel không có cột Email."))

    for _, row in df_upload.iterrows():
        email = str(row.get(email_col, "") or "").strip().lower()
        if not email or not is_valid_register_email(email):
            skipped_count += 1
            continue
        
        password = str(row.get(col_map.get('password'), "") or "").strip() if 'password' in col_map else ""
        if not password:
            password = DEFAULT_FIRST_PASSWORD
            
        note = str(row.get(col_map.get('note'), "") or "").strip() if 'note' in col_map else "Nhập từ Excel"
        if not note:
            note = "Nhập từ Excel"
            
        expiry_val = row.get(col_map.get('expiry'), "") if 'expiry' in col_map else ""
        expires_at = ""
        try:
            days = int(expiry_val)
            if days > 0:
                expires_at = (now + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            expires_at = ""

        existing = df[df["email"].astype(str).str.strip().str.lower() == email]
        if not existing.empty:
            idx = existing.index[0]
            df.at[idx, "status"] = "approved"
            df.at[idx, "password"] = hash_password(password)
            df.at[idx, "raw_password"] = password
            df.at[idx, "note"] = note
            if expires_at:
                df.at[idx, "expires_at"] = expires_at
            df.at[idx, "updated_at"] = now_str
            added_count += 1
        else:
            new_user = {
                "email": email,
                "device_id": str(uuid.uuid4()),
                "active_device_id": "",
                "status": "approved",
                "activation_code": generate_code(),
                "password": hash_password(password),
                "raw_password": password,
                "locked": False,
                "created_at": now_str,
                "updated_at": now_str,
                "note": note,
                "expires_at": expires_at
            }
            df = pd.concat([df, pd.DataFrame([new_user])], ignore_index=True)
            added_count += 1

    save_devices(df)
    msg = f"Đã nhập/cập nhật thành công {added_count} tài khoản. Bỏ qua {skipped_count} dòng không hợp lệ."
    return redirect(f"/admin?pwd={ADMIN_PASSWORD}&msg=" + urllib.parse.quote(msg))


@app.route("/admin/decision", methods=["POST"])
def admin_decision():
  if not is_admin_request():
    return "Không có quyền"

  email = (request.form.get("email") or "").strip().lower()
  action = (request.form.get("action") or "").strip().lower()
  note = (request.form.get("note") or "").strip()
  if not email:
    return redirect("/admin")

  df = load_devices()
  match = df[df["email"].astype(str).str.strip().str.lower() == email]
  if not match.empty:
    idx = match.index[0]
    now = now_vn().strftime("%Y-%m-%d %H:%M:%S")
    if action == "approve":
      df.at[idx, "status"] = "approved"
      df.at[idx, "activation_code"] = generate_code()
      had_password_before = bool(str(df.at[idx, "raw_password"] or "").strip())
      password = generate_password(6) if had_password_before else DEFAULT_FIRST_PASSWORD
      df.at[idx, "password"] = hash_password(password)
      df.at[idx, "raw_password"] = password
      df.at[idx, "locked"] = False
      df.at[idx, "active_device_id"] = ""
      df.at[idx, "updated_at"] = now
      base_note = note or "Đã duyệt"
      existing_note = str(df.at[idx, "note"] or "")
      df.at[idx, "note"] = base_note
      mail_result = send_approval_email(email, password, df.at[idx, "note"])
      if mail_result["success"]:
        df.at[idx, "note"] = base_note
      else:
        if mail_result["msg"] not in existing_note and mail_result["msg"] not in base_note:
          df.at[idx, "note"] = f"{base_note} | {mail_result['msg']}"
        else:
          df.at[idx, "note"] = existing_note or base_note
    elif action == "reject":
      df.at[idx, "status"] = "rejected"
      df.at[idx, "locked"] = False
      df.at[idx, "active_device_id"] = ""
      df.at[idx, "updated_at"] = now
      df.at[idx, "note"] = note or "Từ chối đăng ký"
    else:
      df.at[idx, "updated_at"] = now
      df.at[idx, "note"] = note or df.at[idx, "note"]
    save_devices(df)
  return redirect(f"/admin?pwd={ADMIN_PASSWORD}")


@app.route("/admin/bulk", methods=["POST"])
def admin_bulk():
  if not is_admin_request():
    return "Không có quyền"

  action = (request.form.get("action") or "").strip().lower()
  note = (request.form.get("note") or "").strip()
  selected = request.form.getlist("selected_emails")
  if not selected:
    return redirect(f"/admin?pwd={ADMIN_PASSWORD}")

  df = load_devices()
  now = now_vn().strftime("%Y-%m-%d %H:%M:%S")
  for email in selected:
    email = str(email).strip().lower()
    match = df[df["email"].astype(str).str.strip().str.lower() == email]
    if match.empty:
      continue
    idx = match.index[0]
    if action == "approve":
      df.at[idx, "status"] = "approved"
      df.at[idx, "activation_code"] = generate_code()
      had_password_before = bool(str(df.at[idx, "raw_password"] or "").strip())
      password = generate_password(6) if had_password_before else DEFAULT_FIRST_PASSWORD
      df.at[idx, "password"] = hash_password(password)
      df.at[idx, "raw_password"] = password
      df.at[idx, "locked"] = False
      df.at[idx, "active_device_id"] = ""
      df.at[idx, "updated_at"] = now
      base_note = note or "Đã duyệt hàng loạt"
      existing_note = str(df.at[idx, "note"] or "")
      df.at[idx, "note"] = base_note
      mail_result = send_approval_email(email, password, df.at[idx, "note"])
      if mail_result["success"]:
        df.at[idx, "note"] = base_note
      else:
        if mail_result["msg"] not in existing_note and mail_result["msg"] not in base_note:
          df.at[idx, "note"] = f"{base_note} | {mail_result['msg']}"
        else:
          df.at[idx, "note"] = existing_note or base_note
    elif action == "reject":
      df.at[idx, "status"] = "rejected"
      df.at[idx, "locked"] = False
      df.at[idx, "active_device_id"] = ""
      df.at[idx, "updated_at"] = now
      df.at[idx, "note"] = note or "Từ chối hàng loạt"
  save_devices(df)
  return redirect(f"/admin?pwd={ADMIN_PASSWORD}")


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
  if not is_admin_request():
    return "Không có quyền"

  email = (request.form.get("email") or "").strip().lower()
  if not email:
    return redirect(f"/admin?pwd={ADMIN_PASSWORD}")

  df = load_devices()
  match = df[df["email"].astype(str).str.strip().str.lower() == email]
  if not match.empty:
    df = df.drop(index=match.index[0])
    save_devices(df)
  return redirect(f"/admin?pwd={ADMIN_PASSWORD}")


@app.route("/admin/set_expiry", methods=["POST"])
def admin_set_expiry():
  if not is_admin_request():
    return "Không có quyền"

  email = (request.form.get("email") or "").strip().lower()
  action = (request.form.get("expiry_action") or "").strip().lower()
  if not email:
    return redirect(f"/admin?pwd={ADMIN_PASSWORD}")

  df = load_devices()
  match = df[df["email"].astype(str).str.strip().str.lower() == email]
  if not match.empty:
    idx = match.index[0]
    now = now_vn()
    if action == "clear":
      df.at[idx, "expires_at"] = ""
    elif action == "set":
      try:
        value = int(request.form.get("expiry_value", "0"))
      except Exception:
        value = 0
      unit = (request.form.get("expiry_unit") or "day").strip().lower()
      if value > 0:
        if unit == "month":
          new_expiry = add_months(now, value)
        else:
          new_expiry = now + timedelta(days=value)
        df.at[idx, "expires_at"] = new_expiry.strftime("%Y-%m-%d %H:%M:%S")
    df.at[idx, "updated_at"] = now.strftime("%Y-%m-%d %H:%M:%S")
    save_devices(df)
  return redirect(f"/admin?pwd={ADMIN_PASSWORD}")


def parse_quiz_rows(df):
    items = []
    for idx, row in df.iterrows():
        try:
            question = str(row[1]).strip()
            raw_answers = [str(row[i]).strip() if pd.notna(row[i]) else "" for i in range(2, 6)]
            # Chỉ giữ các đáp án CÓ NỘI DUNG - tránh sinh ra ô tích chọn trống (không chữ)
            # khi câu hỏi thực tế chỉ có 2 hoặc 3 đáp án thay vì đủ 4.
            answers = [a for a in raw_answers if a != ""]
            if question == "" or len(answers) < 2:
                continue
            correct_index = int(str(row[6]).strip()) - 1
            if correct_index < 0 or correct_index > 3:
                continue
            if correct_index >= len(raw_answers) or raw_answers[correct_index] == "":
                continue
            correct_text = raw_answers[correct_index]
            items.append({"id": int(idx), "question": question, "answers": answers, "correctAnswer": correct_text})
        except Exception:
            continue
    return items


def get_current_email():
    return (request.cookies.get("email") or "").strip().lower()


@app.route("/list_files")
def list_files():
    files = [f for f in os.listdir(DATA_DIR) if f.lower().endswith((".xlsx", ".xls", ".csv"))]
    return jsonify(files)


@app.route("/get_info")
def get_info():
    file = request.args.get("file")
    no_repeat = request.args.get("noRepeat") == "1"
    path = os.path.join(DATA_DIR, file)
    try:
        df = pd.read_excel(path, header=None)
        items = parse_quiz_rows(df)
    except Exception:
        items = []

    total = len(items)
    remaining = total
    if no_repeat:
        email = get_current_email()
        used_ids = SESSION_USED_QUESTIONS.get(email, {}).get(file, set())
        remaining = sum(1 for it in items if it["id"] not in used_ids)

    return jsonify({"total": total, "remaining": remaining})


@app.route("/start_quiz", methods=["POST"])
def start_quiz():
    data = request.json or {}
    file = data.get("file")
    num = int(data.get("num", 1))
    no_repeat = bool(data.get("noRepeat"))
    path = os.path.join(DATA_DIR, file)
    try:
        df = pd.read_excel(path, header=None)
        items = parse_quiz_rows(df)
    except Exception:
        return jsonify({"questions": [], "total": 0, "remaining": 0})

    total = len(items)
    if num < 1:
        num = 1

    pool_reset = False
    partial = False

    if no_repeat:
        email = get_current_email()
        if not email:
            return jsonify({"questions": [], "error": "Phiên đăng nhập không hợp lệ. Vui lòng đăng nhập lại."})

        user_used = SESSION_USED_QUESTIONS.setdefault(email, {})
        used_ids = user_used.setdefault(file, set())

        available = [it for it in items if it["id"] not in used_ids]
        if not available and total > 0:
            used_ids.clear()
            available = list(items)
            pool_reset = True

        if len(available) <= num:
            partial = 0 < len(available) < num
            selected = available
        else:
            selected = random.sample(available, num)

        for it in selected:
            used_ids.add(it["id"])
        remaining_after = total - len(used_ids)
        save_used_questions()
    else:
        selected = items if num >= total else random.sample(items, num)
        remaining_after = None

    quiz = []
    for it in selected:
        answers = list(it["answers"])
        random.shuffle(answers)
        quiz.append({"question": it["question"], "options": answers, "correctAnswer": it["correctAnswer"]})
    random.shuffle(quiz)

    now_str = now_vn().strftime("%Y-%m-%d %H:%M:%S")

    return jsonify({
        "questions": quiz,
        "total": total,
        "remaining": remaining_after,
        "poolReset": pool_reset,
        "partial": partial,
        "startedAt": now_str
    })


if __name__ == "__main__":
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    port = int(os.getenv("PORT", "5000"))
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"

    print("=" * 50)
    print(f"Local:   http://127.0.0.1:{port}")
    print(f"LAN:     http://{ip}:{port}")
    if debug_mode:
        print("CẢNH BÁO: đang chạy DEBUG MODE - KHÔNG dùng khi public lên internet!")
    print("=" * 50)

    app.run(host="0.0.0.0", port=port, debug=debug_mode, threaded=True)
