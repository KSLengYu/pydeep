from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
import os
import json
import bcrypt
import uuid
from datetime import datetime, timedelta
from supabase import create_client, Client
from user_agents import parse
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')

# Supabase配置
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# 多个邮箱配置
SMTP_CONFIGS = [
    {
        'host': 'smtp.163.com',
        'port': 587,
        'username': os.environ.get('SMTP_USERNAME_1'),
        'password': os.environ.get('SMTP_PASSWORD_1'),
        'use_tls': True
    },
    {
        'host': 'smtp.163.com',
        'port': 587,
        'username': os.environ.get('SMTP_USERNAME_2'),
        'password': os.environ.get('SMTP_PASSWORD_2'),
        'use_tls': True
    },
    {
        'host': 'smtp.163.com',
        'port': 587,
        'username': os.environ.get('SMTP_USERNAME_3'),
        'password': os.environ.get('SMTP_PASSWORD_3'),
        'use_tls': True
    },
    {
        'host': 'smtp.163.com',
        'port': 587,
        'username': os.environ.get('SMTP_USERNAME_4'),
        'password': os.environ.get('SMTP_PASSWORD_4'),
        'use_tls': True
    },
    {
        'host': 'smtp.163.com',
        'port': 587,
        'username': os.environ.get('SMTP_USERNAME_5'),
        'password': os.environ.get('SMTP_PASSWORD_5'),
        'use_tls': True
    },
    {
        'host': 'smtp.qq.com',
        'port': 587,
        'username': os.environ.get('SMTP_USERNAME_6'),
        'password': os.environ.get('SMTP_PASSWORD_6'),
        'use_tls': True
    }
]

# 获取客户端IP
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

# 获取地理位置
def get_location(ip):
    try:
        response = requests.get(f'https://ipapi.co/{ip}/json/')
        data = response.json()
        if 'error' not in data:
            country = data.get('country_name', '')
            region = data.get('region', '')
            city = data.get('city', '')
            return f"{country} {region} {city}".strip()
    except:
        pass
    return "未知位置"

# 发送验证邮件（随机选择邮箱）
def send_verification_email(email, token):
    try:
        # 随机选择一个邮箱配置
        smtp_config = random.choice(SMTP_CONFIGS)
        
        # 检查配置是否完整
        if not smtp_config['username'] or not smtp_config['password']:
            # 如果随机选择的邮箱配置不完整，尝试其他邮箱
            for config in SMTP_CONFIGS:
                if config['username'] and config['password']:
                    smtp_config = config
                    break
            else:
                return False  # 所有邮箱配置都不完整
        
        verification_url = f"{request.host_url}verify/{token}"
        
        msg = MIMEMultipart()
        msg['From'] = smtp_config['username']
        msg['To'] = email
        msg['Subject'] = "留言板邮箱验证"
        
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background: rgba(0,0,0,0.8); padding: 30px; border-radius: 10px; border: 1px solid #00ffff;">
                <h1 style="text-align: center; color: #00ffff;">科幻留言板</h1>
                <h2 style="color: #00ff00;">邮箱验证</h2>
                <p>请点击下面的链接完成邮箱验证：</p>
                <a href="{verification_url}" style="display: inline-block; background: #00ffff; color: #000; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 20px 0;">验证邮箱</a>
                <p>如果按钮无法点击，请复制以下链接到浏览器：</p>
                <p style="word-break: break-all; color: #00ffff;">{verification_url}</p>
                <p style="color: #ff9900;">此链接24小时内有效</p>
                <p style="color: #cccccc; font-size: 12px; margin-top: 20px;">发送邮箱: {smtp_config['username']}</p>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(smtp_config['host'], smtp_config['port'])
        if smtp_config['use_tls']:
            server.starttls()
        server.login(smtp_config['username'], smtp_config['password'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"发送邮件失败: {e}")
        return False

# 检查游客限制
def check_guest_limit(ip):
    today = datetime.now().date()
    result = supabase.table('guest_limits').select('*').eq('ip_address', ip).execute()
    
    if result.data:
        guest_data = result.data[0]
        last_date = datetime.strptime(guest_data['last_post_date'], '%Y-%m-%d').date()
        
        if last_date != today:
            supabase.table('guest_limits').update({
                'daily_count': 0,
                'last_post_date': today.isoformat()
            }).eq('ip_address', ip).execute()
            return True
        else:
            return guest_data['daily_count'] < 5
    else:
        supabase.table('guest_limits').insert({
            'ip_address': ip,
            'daily_count': 0,
            'last_post_date': today.isoformat()
        }).execute()
        return True

# 增加游客计数
def increment_guest_count(ip):
    today = datetime.now().date()
    result = supabase.table('guest_limits').select('*').eq('ip_address', ip).execute()
    
    if result.data:
        current_count = result.data[0]['daily_count']
        supabase.table('guest_limits').update({
            'daily_count': current_count + 1
        }).eq('ip_address', ip).execute()

# 检查用户是否被封禁
def is_user_banned(user_id):
    result = supabase.table('bans').select('*').eq('user_id', user_id).execute()
    if result.data:
        for ban in result.data:
            expires_at = datetime.fromisoformat(ban['expires_at'].replace('Z', '+00:00'))
            if expires_at > datetime.now().replace(tzinfo=None):
                return True
    return False

# 生成星星背景
def generate_stars():
    stars_html = ""
    for _ in range(100):
        top = random.randint(0, 100)
        left = random.randint(0, 100)
        size = random.randint(1, 3)
        delay = random.randint(0, 5)
        duration = random.randint(3, 8)
        stars_html += f'<div class="star" style="top: {top}%; left: {left}%; width: {size}px; height: {size}px; animation-delay: {delay}s; animation-duration: {duration}s;"></div>'
    return stars_html

@app.route('/')
def index():
    result = supabase.table('messages').select('*, users(*)').is_('parent_id', 'null').order('created_at', desc=True).execute()
    messages = result.data if result.data else []
    
    logs_result = supabase.table('update_logs').select('*').order('created_at', desc=True).execute()
    update_logs = logs_result.data if logs_result.data else []
    
    user_info = None
    if 'user_id' in session:
        user_result = supabase.table('users').select('*').eq('id', session['user_id']).execute()
        if user_result.data:
            user_info = user_result.data[0]
    
    stars_html = generate_stars()
    return render_template('index.html', messages=messages, update_logs=update_logs, user=user_info, stars=stars_html)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        qq_number = data.get('qq_number')
        qq_nickname = data.get('qq_nickname')
        
        existing = supabase.table('users').select('*').eq('email', email).execute()
        if existing.data:
            return jsonify({'success': False, 'message': '邮箱已被注册'})
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        verification_token = str(uuid.uuid4())
        
        user_data = {
            'email': email,
            'password_hash': password_hash,
            'qq_number': qq_number,
            'qq_nickname': qq_nickname,
            'verification_token': verification_token
        }
        
        result = supabase.table('users').insert(user_data).execute()
        
        if result.data:
            if send_verification_email(email, verification_token):
                return jsonify({'success': True, 'message': '注册成功，请查收验证邮件'})
            else:
                return jsonify({'success': False, 'message': '注册成功但邮件发送失败'})
        
        return jsonify({'success': False, 'message': '注册失败'})
    
    stars_html = generate_stars()
    return render_template('register.html', stars=stars_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        result = supabase.table('users').select('*').eq('email', email).execute()
        if not result.data:
            return jsonify({'success': False, 'message': '用户不存在'})
        
        user = result.data[0]
        
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'success': False, 'message': '密码错误'})
        
        if not user['is_verified']:
            return jsonify({'success': False, 'message': '请先验证邮箱'})
        
        if is_user_banned(user['id']):
            return jsonify({'success': False, 'message': '账号已被封禁'})
        
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        session['user_role'] = user['role']
        
        return jsonify({'success': True, 'message': '登录成功'})
    
    stars_html = generate_stars()
    return render_template('login.html', stars=stars_html)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/verify/<token>')
def verify_email(token):
    result = supabase.table('users').select('*').eq('verification_token', token).execute()
    
    if result.data:
        user = result.data[0]
        supabase.table('users').update({
            'is_verified': True,
            'verification_token': None
        }).eq('id', user['id']).execute()
        
        return redirect(url_for('login'))
    
    return "验证链接无效或已过期"

@app.route('/post_message', methods=['POST'])
def post_message():
    data = request.get_json()
    content = data.get('content')
    parent_id = data.get('parent_id')
    
    if not content:
        return jsonify({'success': False, 'message': '内容不能为空'})
    
    ip = get_client_ip()
    location = get_location(ip)
    user_agent = parse(request.headers.get('User-Agent'))
    device_info = f"{user_agent.device.family} {user_agent.device.model}".strip()
    if not device_info or device_info == "Other Other":
        device_info = user_agent.os.family
    
    if 'user_id' in session:
        user_id = session['user_id']
        
        if is_user_banned(user_id):
            return jsonify({'success': False, 'message': '账号已被封禁'})
    else:
        user_id = None
        if not check_guest_limit(ip):
            return jsonify({'success': False, 'message': '游客每日只能发布5条留言'})
    
    message_data = {
        'content': content,
        'parent_id': parent_id,
        'ip_address': ip,
        'location': location,
        'device_info': device_info,
        'user_agent': str(user_agent)
    }
    
    if user_id:
        message_data['user_id'] = user_id
    
    result = supabase.table('messages').insert(message_data).execute()
    
    if result.data:
        if not user_id:
            increment_guest_count(ip)
        
        return jsonify({'success': True, 'message': '发布成功'})
    
    return jsonify({'success': False, 'message': '发布失败'})

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_result = supabase.table('users').select('*').eq('id', session['user_id']).execute()
    if not user_result.data:
        session.clear()
        return redirect(url_for('login'))
    
    user = user_result.data[0]
    stars_html = generate_stars()
    return render_template('profile.html', user=user, stars=stars_html)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录'})
    
    data = request.get_json()
    qq_number = data.get('qq_number')
    qq_nickname = data.get('qq_nickname')
    
    update_data = {}
    if qq_number is not None:
        update_data['qq_number'] = qq_number
    if qq_nickname is not None:
        update_data['qq_nickname'] = qq_nickname
    
    if update_data:
        supabase.table('users').update(update_data).eq('id', session['user_id']).execute()
    
    return jsonify({'success': True, 'message': '更新成功'})

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': '请先登录'})
    
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    user_result = supabase.table('users').select('*').eq('id', session['user_id']).execute()
    if not user_result.data:
        return jsonify({'success': False, 'message': '用户不存在'})
    
    user = user_result.data[0]
    
    if not bcrypt.checkpw(current_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'success': False, 'message': '当前密码错误'})
    
    new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    supabase.table('users').update({'password_hash': new_password_hash}).eq('id', session['user_id']).execute()
    
    return jsonify({'success': True, 'message': '密码修改成功'})

@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'super_admin']:
        return redirect(url_for('index'))
    
    users_result = supabase.table('users').select('*').execute()
    users = users_result.data if users_result.data else []
    
    messages_result = supabase.table('messages').select('*, users(*)').execute()
    messages = messages_result.data if messages_result.data else []
    
    bans_result = supabase.table('bans').select('*, users!bans_user_id_fkey(*), users!bans_banned_by_fkey(*)').execute()
    bans = bans_result.data if bans_result.data else []
    
    stars_html = generate_stars()
    return render_template('admin.html', users=users, messages=messages, bans=bans, stars=stars_html)

@app.route('/admin/update_role', methods=['POST'])
def update_role():
    if 'user_id' not in session or session.get('user_role') != 'super_admin':
        return jsonify({'success': False, 'message': '权限不足'})
    
    data = request.get_json()
    user_id = data.get('user_id')
    new_role = data.get('role')
    
    if new_role not in ['user', 'admin', 'super_admin']:
        return jsonify({'success': False, 'message': '无效的角色'})
    
    supabase.table('users').update({'role': new_role}).eq('id', user_id).execute()
    
    return jsonify({'success': True, 'message': '角色更新成功'})

@app.route('/admin/delete_message', methods=['POST'])
def delete_message():
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'super_admin']:
        return jsonify({'success': False, 'message': '权限不足'})
    
    data = request.get_json()
    message_id = data.get('message_id')
    
    supabase.table('messages').update({'is_deleted': True}).eq('id', message_id).execute()
    
    return jsonify({'success': True, 'message': '留言已删除'})

@app.route('/admin/ban_user', methods=['POST'])
def ban_user():
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'super_admin']:
        return jsonify({'success': False, 'message': '权限不足'})
    
    data = request.get_json()
    user_id = data.get('user_id')
    reason = data.get('reason', '')
    days = data.get('days', 7)
    
    expires_at = datetime.now() + timedelta(days=days)
    
    ban_data = {
        'user_id': user_id,
        'banned_by': session['user_id'],
        'reason': reason,
        'expires_at': expires_at.isoformat()
    }
    
    supabase.table('bans').insert(ban_data).execute()
    
    return jsonify({'success': True, 'message': '用户已封禁'})

@app.route('/toggle_fold', methods=['POST'])
def toggle_fold():
    data = request.get_json()
    message_id = data.get('message_id')
    
    result = supabase.table('messages').select('is_folded').eq('id', message_id).execute()
    if result.data:
        current_state = result.data[0]['is_folded']
        supabase.table('messages').update({'is_folded': not current_state}).eq('id', message_id).execute()
        
        return jsonify({'success': True, 'folded': not current_state})
    
    return jsonify({'success': False})

@app.route('/get_replies/<message_id>')
def get_replies(message_id):
    result = supabase.table('messages').select('*, users(*)').eq('parent_id', message_id).order('created_at').execute()
    replies = result.data if result.data else []
    
    return jsonify(replies)

if __name__ == '__main__':
    app.run(debug=True)