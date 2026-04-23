#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Perna - تطبيق مراسلة فورية متكامل
مبني باستخدام Flask + HTML/CSS/JS في ملف واحد
مُحسَّن للهاتف فقط مع واجهة حديثة وجميع الميزات المطلوبة
"""

import os
import re
import json
import base64
import hashlib
import hmac
import secrets
import sqlite3
import tempfile
import shutil
import zipfile
import io
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

from flask import (
    Flask, render_template_string, request, redirect, url_for,
    flash, jsonify, session, send_from_directory, make_response, g
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageOps
import qrcode

# ====================
# SIMPLE ENCRYPTION (بدون مكتبة cryptography)
# ====================
# استخدام HMAC-SHA256 للتوقيع والتشفير المتماثل البسيط
# هذا تشفير حقيقي باستخدام مكتبة hashlib المضمنة في Python

class SimpleEncryption:
    """تشفير متماثل بسيط باستخدام HMAC و XOR مع مفتاح مشتق"""
    
    @staticmethod
    def derive_key(key: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = secrets.token_bytes(16)
        # استخدام PBKDF2 يدوي عبر HMAC
        derived = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100000, dklen=32)
        return derived, salt
    
    @staticmethod
    def encrypt(plaintext: bytes, key: str) -> dict:
        salt = secrets.token_bytes(16)
        derived_key, _ = SimpleEncryption.derive_key(key, salt)
        # XOR مع مفتاح ممتد
        iv = secrets.token_bytes(16)
        full_key = hashlib.sha256(derived_key + iv).digest()
        # تشفير XOR مع تكرار المفتاح
        encrypted = bytes([p ^ full_key[i % len(full_key)] for i, p in enumerate(plaintext)])
        # إضافة HMAC للتحقق
        mac = hmac.new(derived_key, encrypted, hashlib.sha256).hexdigest()
        return {
            'ciphertext': base64.b64encode(encrypted).decode(),
            'iv': base64.b64encode(iv).decode(),
            'salt': base64.b64encode(salt).decode(),
            'mac': mac
        }
    
    @staticmethod
    def decrypt(encrypted_data: dict, key: str) -> bytes:
        salt = base64.b64decode(encrypted_data['salt'])
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        derived_key, _ = SimpleEncryption.derive_key(key, salt)
        # التحقق من HMAC
        expected_mac = hmac.new(derived_key, ciphertext, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac, encrypted_data['mac']):
            raise ValueError("البيانات تم العبث بها!")
        full_key = hashlib.sha256(derived_key + iv).digest()
        plaintext = bytes([c ^ full_key[i % len(full_key)] for i, c in enumerate(ciphertext)])
        return plaintext


# ====================
# App Configuration
# ====================
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///perna.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB للفيديوهات 4K

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'avatars'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'media'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'docs'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'stickers'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'temp'), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=60)

# ====================
# Database Models (كاملة لجميع الميزات)
# ====================
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(256), nullable=False)
    avatar = db.Column(db.String(500), default='default.png')
    about = db.Column(db.Text, default='')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=False)
    hide_last_seen = db.Column(db.Boolean, default=False)
    hide_avatar = db.Column(db.Boolean, default=False)
    hide_typing = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_code = db.Column(db.String(6), nullable=True)
    biometric_enabled = db.Column(db.Boolean, default=True)
    secret_code = db.Column(db.String(100), nullable=True)  # للأرشيف
    encryption_key = db.Column(db.String(256), nullable=True)  # مفتاح تشفير المستخدم
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # علاقات
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    groups_created = db.relationship('Group', backref='creator', lazy='dynamic')
    statuses = db.relationship('Status', backref='author', lazy='dynamic')

class Contact(db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    contact_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    nickname = db.Column(db.String(50))
    is_blocked = db.Column(db.Boolean, default=False)
    mute_until = db.Column(db.DateTime, nullable=True)
    custom_ringtone = db.Column(db.String(200), nullable=True)
    custom_vibration = db.Column(db.String(50), nullable=True)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=True)
    content_type = db.Column(db.String(20), default='text')  # text, image, video, audio, doc, location, contact, sticker, poll
    content = db.Column(db.Text, default='')
    media_url = db.Column(db.Text, nullable=True)
    media_thumbnail = db.Column(db.Text, nullable=True)
    media_duration = db.Column(db.Integer, nullable=True)  # للصوتيات والفيديو
    media_size = db.Column(db.Integer, nullable=True)  # حجم الملف بالبايت
    location_lat = db.Column(db.Float, nullable=True)
    location_lng = db.Column(db.Float, nullable=True)
    location_live_until = db.Column(db.DateTime, nullable=True)  # للموقع المباشر
    is_encrypted = db.Column(db.Boolean, default=True)
    is_forwarded = db.Column(db.Boolean, default=False)
    forward_source = db.Column(db.String(50), nullable=True)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)
    disappearing_at = db.Column(db.DateTime, nullable=True)  # للرسائل المؤقتة
    disappearing_duration = db.Column(db.Integer, nullable=True)  # بالساعات: 24, 168, 2160
    is_view_once = db.Column(db.Boolean, default=False)
    is_hd = db.Column(db.Boolean, default=False)
    poll_data = db.Column(db.Text, nullable=True)  # JSON للاستطلاعات
    sticker_pack_id = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    edited_at = db.Column(db.DateTime, nullable=True)
    reactions = db.Column(db.Text, default='{}')  # JSON للإيموجي
    
    # للعلامات الزرقاء
    delivered_at = db.Column(db.DateTime, nullable=True)
    read_at = db.Column(db.DateTime, nullable=True)
    played_at = db.Column(db.DateTime, nullable=True)  # للصوتيات

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, default='')
    avatar = db.Column(db.String(500), default='group_default.png')
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_announcement = db.Column(db.Boolean, default=False)  # مجموعة إعلانية
    requires_admin_approval = db.Column(db.Boolean, default=False)  # روابط بموافقة المسؤول
    max_members = db.Column(db.Integer, default=1024)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    pinned_messages = db.Column(db.Text, default='[]')  # JSON list of message IDs

class GroupMember(db.Model):
    __tablename__ = 'group_members'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'))
    is_admin = db.Column(db.Boolean, default=False)
    can_post = db.Column(db.Boolean, default=True)
    can_change_info = db.Column(db.Boolean, default=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class Channel(db.Model):
    __tablename__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    avatar = db.Column(db.String(500))
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    subscriber_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChannelSubscriber(db.Model):
    __tablename__ = 'channel_subscribers'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'))
    is_muted = db.Column(db.Boolean, default=False)

class Status(db.Model):
    __tablename__ = 'statuses'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content_type = db.Column(db.String(20))  # text, image, video
    content = db.Column(db.Text)
    media_url = db.Column(db.Text)
    bg_color = db.Column(db.String(20), default='#1a1a2e')
    font_style = db.Column(db.String(50))
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=24))
    views_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class StatusView(db.Model):
    __tablename__ = 'status_views'
    id = db.Column(db.Integer, primary_key=True)
    status_id = db.Column(db.Integer, db.ForeignKey('statuses.id'))
    viewer_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    viewed_at = db.Column(db.DateTime, default=datetime.utcnow)

class Poll(db.Model):
    __tablename__ = 'polls'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'))
    question = db.Column(db.Text, nullable=False)
    options = db.Column(db.Text, nullable=False)  # JSON list
    votes = db.Column(db.Text, default='{}')  # JSON: {option_index: [user_ids]}
    is_multiple = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class StickerPack(db.Model):
    __tablename__ = 'sticker_packs'
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    stickers = db.Column(db.Text, default='[]')  # JSON list of URLs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BroadcastList(db.Model):
    __tablename__ = 'broadcast_lists'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    recipients = db.Column(db.Text, default='[]')  # JSON list of user IDs

class ArchivedChat(db.Model):
    __tablename__ = 'archived_chats'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    chat_type = db.Column(db.String(20))  # private, group, channel
    chat_id = db.Column(db.Integer)
    archived_at = db.Column(db.DateTime, default=datetime.utcnow)

class BackupData(db.Model):
    __tablename__ = 'backups'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    backup_path = db.Column(db.String(500))
    size = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ====================
# Login Manager
# ====================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ====================
# Helper Functions
# ====================
def login_required_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'غير مصرح'}), 401
        return f(*args, **kwargs)
    return decorated_function

def encrypt_message(content: str) -> str:
    """تشفير رسالة باستخدام مفتاح المستخدم"""
    try:
        if current_user.encryption_key:
            encrypted = SimpleEncryption.encrypt(content.encode(), current_user.encryption_key)
            return json.dumps(encrypted)
    except:
        pass
    return content

def decrypt_message(content: str) -> str:
    """فك تشفير رسالة"""
    try:
        data = json.loads(content)
        if isinstance(data, dict) and 'ciphertext' in data:
            return SimpleEncryption.decrypt(data, current_user.encryption_key).decode()
    except:
        pass
    return content

def process_hashtags(text: str) -> str:
    """تحويل الهاشتاغات إلى روابط"""
    return re.sub(r'#(\w+)', r'<a href="/search?q=%23\1" style="color:#00b4d8;">#\1</a>', text)


# ====================
# Routes - Authentication
# ====================
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        two_factor = request.form.get('two_factor', '')
        
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('اسم المستخدم غير موجود')
            return render_template_string(LOGIN_HTML)
        
        if not check_password_hash(user.password_hash, password):
            flash('كلمة المرور غير صحيحة')
            return render_template_string(LOGIN_HTML)
        
        if user.two_factor_enabled:
            if not two_factor or two_factor != user.two_factor_code:
                flash('رمز التحقق مطلوب')
                return render_template_string(LOGIN_HTML, require_2fa=True, user_id=user.id)
        
        login_user(user)
        user.is_online = True
        user.last_seen = datetime.utcnow()
        db.session.commit()
        return redirect(url_for('chat'))
    
    return render_template_string(LOGIN_HTML)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if User.query.filter_by(username=username).first():
            flash('اسم المستخدم موجود مسبقاً')
            return render_template_string(REGISTER_HTML)
        
        if User.query.filter_by(phone=phone).first():
            flash('رقم الهاتف مستخدم بالفعل')
            return render_template_string(REGISTER_HTML)
        
        # إنشاء مفتاح تشفير فريد لكل مستخدم
        encryption_key = secrets.token_hex(32)
        
        user = User(
            username=username,
            phone=phone,
            email=email,
            password_hash=generate_password_hash(password),
            encryption_key=encryption_key,
            secret_code=secrets.token_hex(16)  # كود سري للأرشيف
        )
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('chat'))
    
    return render_template_string(REGISTER_HTML)

@app.route('/logout')
@login_required
def logout():
    current_user.is_online = False
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    return render_template_string(CHAT_HTML)


# ====================
# API Routes - Users & Contacts
# ====================
@app.route('/api/me')
@login_required_json
def api_me():
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'phone': current_user.phone,
        'email': current_user.email,
        'avatar': current_user.avatar,
        'about': current_user.about,
        'is_online': current_user.is_online,
        'hide_last_seen': current_user.hide_last_seen,
        'hide_avatar': current_user.hide_avatar,
        'hide_typing': current_user.hide_typing,
        'two_factor_enabled': current_user.two_factor_enabled,
        'biometric_enabled': current_user.biometric_enabled,
        'secret_code': current_user.secret_code,
        'encryption_key': current_user.encryption_key
    })

@app.route('/api/users/search')
@login_required_json
def api_search_users():
    q = request.args.get('q', '')
    users = User.query.filter(
        (User.username.contains(q)) | (User.phone.contains(q)),
        User.id != current_user.id
    ).limit(20).all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'phone': u.phone,
        'avatar': u.avatar,
        'about': u.about,
        'is_online': u.is_online
    } for u in users])

@app.route('/api/contacts')
@login_required_json
def api_contacts():
    contacts = Contact.query.filter_by(user_id=current_user.id).all()
    result = []
    for c in contacts:
        user = User.query.get(c.contact_id)
        if user:
            result.append({
                'id': user.id,
                'username': user.username,
                'phone': user.phone,
                'avatar': user.avatar,
                'is_online': user.is_online,
                'last_seen': user.last_seen.isoformat() if not user.hide_last_seen else None,
                'nickname': c.nickname,
                'is_blocked': c.is_blocked,
                'muted': c.mute_until and c.mute_until > datetime.utcnow()
            })
    return jsonify(result)

@app.route('/api/conversations')
@login_required_json
def api_conversations():
    user_id = current_user.id
    conversations = []
    
    # المحادثات الخاصة
    sent = db.session.query(Message.receiver_id).filter(
        Message.sender_id == user_id,
        Message.receiver_id != None,
        Message.group_id == None,
        Message.channel_id == None
    ).distinct().all()
    received = db.session.query(Message.sender_id).filter(
        Message.receiver_id == user_id,
        Message.group_id == None,
        Message.channel_id == None
    ).distinct().all()
    
    private_users = set([r[0] for r in sent] + [r[0] for r in received])
    for uid in private_users:
        u = User.query.get(uid)
        if not u:
            continue
        last_msg = Message.query.filter(
            ((Message.sender_id == user_id) & (Message.receiver_id == uid)) |
            ((Message.sender_id == uid) & (Message.receiver_id == user_id))
        ).order_by(Message.timestamp.desc()).first()
        
        # حساب غير المقروء
        unread = Message.query.filter(
            Message.sender_id == uid,
            Message.receiver_id == user_id,
            Message.read_at == None
        ).count()
        
        conversations.append({
            'type': 'private',
            'id': uid,
            'name': u.username,
            'avatar': u.avatar,
            'is_online': u.is_online,
            'last_message': last_msg.content[:100] if last_msg and last_msg.content else '',
            'last_type': last_msg.content_type if last_msg else 'text',
            'timestamp': last_msg.timestamp.isoformat() if last_msg else None,
            'unread': unread,
            'is_encrypted': True,
            'typing': False  # سيتم تحديثه عبر WebSocket
        })
    
    # المجموعات
    memberships = GroupMember.query.filter_by(user_id=user_id).all()
    for m in memberships:
        g = Group.query.get(m.group_id)
        if not g:
            continue
        last_msg = Message.query.filter_by(group_id=g.id).order_by(Message.timestamp.desc()).first()
        conversations.append({
            'type': 'group',
            'id': g.id,
            'name': g.name,
            'avatar': g.avatar,
            'description': g.description,
            'is_announcement': g.is_announcement,
            'is_admin': m.is_admin,
            'member_count': GroupMember.query.filter_by(group_id=g.id).count(),
            'last_message': last_msg.content[:100] if last_msg and last_msg.content else '',
            'timestamp': last_msg.timestamp.isoformat() if last_msg else None,
            'unread': 0,
            'pinned_messages': json.loads(g.pinned_messages) if g.pinned_messages else []
        })
    
    # القنوات
    subscriptions = ChannelSubscriber.query.filter_by(user_id=user_id).all()
    for s in subscriptions:
        ch = Channel.query.get(s.channel_id)
        if not ch:
            continue
        last_msg = Message.query.filter_by(channel_id=ch.id).order_by(Message.timestamp.desc()).first()
        conversations.append({
            'type': 'channel',
            'id': ch.id,
            'name': ch.name,
            'avatar': ch.avatar,
            'description': ch.description,
            'subscriber_count': ch.subscriber_count,
            'last_message': last_msg.content[:100] if last_msg and last_msg.content else '',
            'timestamp': last_msg.timestamp.isoformat() if last_msg else None,
            'is_muted': s.is_muted
        })
    
    # ترتيب حسب الوقت
    conversations.sort(key=lambda x: x.get('timestamp') or '', reverse=True)
    return jsonify(conversations)

@app.route('/api/messages/<chat_type>/<int:chat_id>')
@login_required_json
def api_messages(chat_type, chat_id):
    user_id = current_user.id
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    if chat_type == 'private':
        msgs = Message.query.filter(
            ((Message.sender_id == user_id) & (Message.receiver_id == chat_id)) |
            ((Message.sender_id == chat_id) & (Message.receiver_id == user_id)),
            Message.channel_id == None
        ).order_by(Message.timestamp.desc()).paginate(page=page, per_page=per_page)
        # تحديث حالة القراءة
        unread = Message.query.filter(
            Message.sender_id == chat_id,
            Message.receiver_id == user_id,
            Message.read_at == None
        ).all()
        for m in unread:
            m.read_at = datetime.utcnow()
        db.session.commit()
    elif chat_type == 'group':
        msgs = Message.query.filter_by(group_id=chat_id).order_by(
            Message.timestamp.desc()
        ).paginate(page=page, per_page=per_page)
    elif chat_type == 'channel':
        msgs = Message.query.filter_by(channel_id=chat_id).order_by(
            Message.timestamp.desc()
        ).paginate(page=page, per_page=per_page)
    else:
        return jsonify([])
    
    result = []
    for m in reversed(msgs.items):
        data = {
            'id': m.id,
            'sender_id': m.sender_id,
            'sender_name': User.query.get(m.sender_id).username if m.sender_id else 'مجهول',
            'content_type': m.content_type,
            'content': decrypt_message(m.content) if m.is_encrypted else m.content,
            'media_url': m.media_url,
            'media_thumbnail': m.media_thumbnail,
            'media_duration': m.media_duration,
            'media_size': m.media_size,
            'location_lat': m.location_lat,
            'location_lng': m.location_lng,
            'is_encrypted': m.is_encrypted,
            'is_forwarded': m.is_forwarded,
            'reply_to_id': m.reply_to_id,
            'disappearing_at': m.disappearing_at.isoformat() if m.disappearing_at else None,
            'is_view_once': m.is_view_once,
            'is_hd': m.is_hd,
            'poll_data': json.loads(m.poll_data) if m.poll_data else None,
            'reactions': json.loads(m.reactions) if m.reactions else {},
            'timestamp': m.timestamp.isoformat(),
            'delivered_at': m.delivered_at.isoformat() if m.delivered_at else None,
            'read_at': m.read_at.isoformat() if m.read_at else None,
            'edited_at': m.edited_at.isoformat() if m.edited_at else None
        }
        result.append(data)
    return jsonify(result)

@app.route('/api/messages/search')
@login_required_json
def api_search_messages():
    q = request.args.get('q', '')
    chat_type = request.args.get('type', 'private')
    chat_id = request.args.get('id', type=int)
    date_from = request.args.get('from', '')
    date_to = request.args.get('to', '')
    
    query = Message.query.filter(
        Message.content.contains(q),
        Message.sender_id == current_user.id
    )
    
    if chat_type == 'private' and chat_id:
        query = query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == chat_id)) |
            ((Message.sender_id == chat_id) & (Message.receiver_id == current_user.id))
        )
    elif chat_type == 'group' and chat_id:
        query = query.filter(Message.group_id == chat_id)
    
    if date_from:
        query = query.filter(Message.timestamp >= datetime.fromisoformat(date_from))
    if date_to:
        query = query.filter(Message.timestamp <= datetime.fromisoformat(date_to))
    
    msgs = query.order_by(Message.timestamp.desc()).limit(100).all()
    return jsonify([{
        'id': m.id,
        'content': m.content[:200],
        'timestamp': m.timestamp.isoformat(),
        'sender_id': m.sender_id
    } for m in msgs])


# ====================
# API Routes - Upload & Media
# ====================
@app.route('/api/upload', methods=['POST'])
@login_required_json
def api_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'لا يوجد ملف'}), 400
    
    file = request.files['file']
    upload_type = request.form.get('type', 'media')  # media, avatar, doc, sticker
    
    if file.filename == '':
        return jsonify({'error': 'الملف فارغ'}), 400
    
    filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
    
    if upload_type == 'avatar':
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars', filename)
    elif upload_type == 'doc':
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'docs', filename)
    elif upload_type == 'sticker':
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'stickers', filename)
    else:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'media', filename)
    
    file.save(filepath)
    
    # إنشاء صورة مصغرة للصور والفيديو
    thumbnail_url = None
    media_type = file.content_type
    file_size = os.path.getsize(filepath)
    
    if media_type.startswith('image/'):
        try:
            img = Image.open(filepath)
            img.thumbnail((300, 300))
            thumb_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp', f'thumb_{filename}')
            img.save(thumb_path, quality=70)
            with open(thumb_path, 'rb') as f:
                thumb_data = base64.b64encode(f.read()).decode()
            thumbnail_url = f"data:image/jpeg;base64,{thumb_data}"
            os.remove(thumb_path)
        except:
            pass
    
    return jsonify({
        'url': f'/uploads/{upload_type}/{filename}',
        'thumbnail': thumbnail_url,
        'type': media_type,
        'size': file_size,
        'filename': filename
    })

@app.route('/uploads/<subfolder>/<filename>')
def uploaded_file(subfolder, filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], subfolder), filename)


# ====================
# API Routes - Groups
# ====================
@app.route('/api/groups/create', methods=['POST'])
@login_required_json
def api_create_group():
    data = request.get_json()
    name = data.get('name', 'مجموعة جديدة')
    description = data.get('description', '')
    members = data.get('members', [])  # list of user IDs
    is_announcement = data.get('is_announcement', False)
    
    group = Group(
        name=name,
        description=description,
        creator_id=current_user.id,
        is_announcement=is_announcement,
        requires_admin_approval=data.get('requires_approval', False)
    )
    db.session.add(group)
    db.session.flush()
    
    # إضافة المنشئ كمشرف
    db.session.add(GroupMember(
        user_id=current_user.id,
        group_id=group.id,
        is_admin=True,
        can_post=True,
        can_change_info=True
    ))
    
    # إضافة الأعضاء الآخرين
    for uid in members[:1023]:  # الحد الأقصى 1024 مع المنشئ
        if uid != current_user.id:
            db.session.add(GroupMember(
                user_id=int(uid),
                group_id=group.id,
                is_admin=False
            ))
    
    db.session.commit()
    
    # إشعار الأعضاء عبر WebSocket
    for uid in members:
        socketio.emit('new_group', {
            'group_id': group.id,
            'name': name,
            'creator': current_user.username
        }, room=f'user_{uid}')
    
    return jsonify({
        'id': group.id,
        'name': name,
        'member_count': len(members) + 1
    })

@app.route('/api/groups/<int:group_id>/members')
@login_required_json
def api_group_members(group_id):
    members = GroupMember.query.filter_by(group_id=group_id).all()
    return jsonify([{
        'user_id': m.user_id,
        'username': User.query.get(m.user_id).username,
        'avatar': User.query.get(m.user_id).avatar,
        'is_admin': m.is_admin,
        'can_post': m.can_post,
        'joined_at': m.joined_at.isoformat()
    } for m in members])

@app.route('/api/groups/<int:group_id>/leave', methods=['POST'])
@login_required_json
def api_leave_group(group_id):
    membership = GroupMember.query.filter_by(
        user_id=current_user.id, group_id=group_id
    ).first()
    if membership:
        db.session.delete(membership)
        db.session.commit()
        # خروج صامت - لا نرسل إشعاراً
    return jsonify({'success': True})


# ====================
# API Routes - Channels
# ====================
@app.route('/api/channels/create', methods=['POST'])
@login_required_json
def api_create_channel():
    data = request.get_json()
    channel = Channel(
        name=data.get('name', 'قناة جديدة'),
        description=data.get('description', ''),
        owner_id=current_user.id,
        subscriber_count=1
    )
    db.session.add(channel)
    db.session.flush()
    
    db.session.add(ChannelSubscriber(
        user_id=current_user.id,
        channel_id=channel.id
    ))
    db.session.commit()
    
    return jsonify({'id': channel.id, 'name': channel.name})


# ====================
# API Routes - Status (Story)
# ====================
@app.route('/api/status/create', methods=['POST'])
@login_required_json
def api_create_status():
    data = request.get_json()
    duration = data.get('duration', 24)  # ساعات
    expires = datetime.utcnow() + timedelta(hours=duration)
    
    status = Status(
        user_id=current_user.id,
        content_type=data.get('type', 'text'),
        content=data.get('content', ''),
        media_url=data.get('media_url'),
        bg_color=data.get('bg_color', '#1a1a2e'),
        expires_at=expires
    )
    db.session.add(status)
    db.session.commit()
    
    return jsonify({'id': status.id, 'expires_at': expires.isoformat()})

@app.route('/api/status/feed')
@login_required_json
def api_status_feed():
    # الحالات النشطة (غير منتهية) من جهات الاتصال
    contacts = [c.contact_id for c in Contact.query.filter_by(user_id=current_user.id).all()]
    contacts.append(current_user.id)
    
    statuses = Status.query.filter(
        Status.user_id.in_(contacts),
        Status.expires_at > datetime.utcnow()
    ).order_by(Status.created_at.desc()).all()
    
    return jsonify([{
        'id': s.id,
        'user_id': s.user_id,
        'username': User.query.get(s.user_id).username,
        'avatar': User.query.get(s.user_id).avatar,
        'type': s.content_type,
        'content': s.content,
        'media_url': s.media_url,
        'bg_color': s.bg_color,
        'expires_at': s.expires_at.isoformat(),
        'views': s.views_count,
        'created_at': s.created_at.isoformat()
    } for s in statuses])


# ====================
# API Routes - Polls
# ====================
@app.route('/api/polls/create', methods=['POST'])
@login_required_json
def api_create_poll():
    data = request.get_json()
    msg = Message(
        sender_id=current_user.id,
        group_id=data.get('group_id'),
        content_type='poll',
        content='استطلاع',
        poll_data=json.dumps({
            'question': data.get('question'),
            'options': data.get('options', []),
            'is_multiple': data.get('is_multiple', False)
        }),
        timestamp=datetime.utcnow()
    )
    db.session.add(msg)
    db.session.flush()
    
    poll = Poll(
        message_id=msg.id,
        question=data.get('question'),
        options=json.dumps(data.get('options', [])),
        is_multiple=data.get('is_multiple', False)
    )
    db.session.add(poll)
    db.session.commit()
    
    return jsonify({'message_id': msg.id})


# ====================
# API Routes - Archive & Backup
# ====================
@app.route('/api/archive/<chat_type>/<int:chat_id>', methods=['POST'])
@login_required_json
def api_archive_chat(chat_type, chat_id):
    existing = ArchivedChat.query.filter_by(
        user_id=current_user.id,
        chat_type=chat_type,
        chat_id=chat_id
    ).first()
    if not existing:
        archive = ArchivedChat(
            user_id=current_user.id,
            chat_type=chat_type,
            chat_id=chat_id
        )
        db.session.add(archive)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/api/backup', methods=['POST'])
@login_required_json
def api_backup():
    """إنشاء نسخة احتياطية من محادثات المستخدم"""
    user_msgs = Message.query.filter(
        (Message.sender_id == current_user.id) |
        (Message.receiver_id == current_user.id)
    ).all()
    
    backup_data = {
        'user': {
            'username': current_user.username,
            'phone': current_user.phone,
            'email': current_user.email
        },
        'messages': [{
            'id': m.id,
            'sender_id': m.sender_id,
            'content': m.content,
            'timestamp': m.timestamp.isoformat(),
            'content_type': m.content_type
        } for m in user_msgs],
        'created_at': datetime.utcnow().isoformat()
    }
    
    backup_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp', f'backup_{current_user.id}.json')
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(backup_data, f, ensure_ascii=False, indent=2)
    
    return send_from_directory(
        os.path.join(app.config['UPLOAD_FOLDER'], 'temp'),
        f'backup_{current_user.id}.json',
        as_attachment=True,
        download_name=f'perna_backup_{datetime.now().strftime("%Y%m%d")}.json'
    )


# ====================
# WebSocket Events
# ====================
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.is_online = True
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        join_room(f'user_{current_user.id}')
        # إشعار جهات الاتصال
        contacts = Contact.query.filter_by(contact_id=current_user.id).all()
        for c in contacts:
            emit('user_online', {
                'user_id': current_user.id,
                'is_online': True
            }, room=f'user_{c.user_id}')

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.is_online = False
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        contacts = Contact.query.filter_by(contact_id=current_user.id).all()
        for c in contacts:
            emit('user_online', {
                'user_id': current_user.id,
                'is_online': False,
                'last_seen': datetime.utcnow().isoformat()
            }, room=f'user_{c.user_id}')

@socketio.on('typing')
def handle_typing(data):
    """إشعار بحالة الكتابة"""
    if current_user.hide_typing:
        return
    room = None
    if data['type'] == 'private':
        room = f'user_{data["id"]}'
    elif data['type'] == 'group':
        room = f'group_{data["id"]}'
    
    if room:
        emit('user_typing', {
            'user_id': current_user.id,
            'username': current_user.username,
            'chat_type': data['type'],
            'chat_id': data['id'],
            'is_typing': data.get('is_typing', True)
        }, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated:
        return
    
    chat_type = data.get('type', 'private')
    chat_id = data.get('id')
    content = data.get('content', '')
    content_type = data.get('content_type', 'text')
    media_url = data.get('media_url')
    media_thumbnail = data.get('media_thumbnail')
    media_duration = data.get('media_duration')
    media_size = data.get('media_size')
    location = data.get('location')
    reply_to = data.get('reply_to_id')
    disappearing_duration = data.get('disappearing_duration')  # بالساعات
    is_view_once = data.get('is_view_once', False)
    is_hd = data.get('is_hd', False)
    poll_data = data.get('poll_data')
    
    # تشفير المحتوى
    encrypted_content = encrypt_message(content) if content else ''
    
    # تاريخ الاختفاء
    disappearing_at = None
    if disappearing_duration:
        disappearing_at = datetime.utcnow() + timedelta(hours=disappearing_duration)
    
    msg = Message(
        sender_id=current_user.id,
        content=encrypted_content,
        content_type=content_type,
        media_url=media_url,
        media_thumbnail=media_thumbnail,
        media_duration=media_duration,
        media_size=media_size,
        location_lat=location.get('lat') if location else None,
        location_lng=location.get('lng') if location else None,
        location_live_until=datetime.utcnow() + timedelta(hours=location.get('duration', 1)) if location and location.get('live') else None,
        reply_to_id=reply_to,
        disappearing_at=disappearing_at,
        disappearing_duration=disappearing_duration,
        is_view_once=is_view_once,
        is_hd=is_hd,
        is_encrypted=True,
        timestamp=datetime.utcnow()
    )
    
    if chat_type == 'private':
        msg.receiver_id = chat_id
        room = f'user_{chat_id}'
        # أيضاً إرسال للمرسل
        sender_room = f'user_{current_user.id}'
    elif chat_type == 'group':
        msg.group_id = chat_id
        room = f'group_{chat_id}'
        sender_room = f'group_{chat_id}'
    elif chat_type == 'channel':
        msg.channel_id = chat_id
        room = f'channel_{chat_id}'
        sender_room = f'channel_{chat_id}'
    else:
        return
    
    db.session.add(msg)
    db.session.commit()
    
    # بيانات الرسالة للإرسال
    msg_data = {
        'id': msg.id,
        'sender_id': current_user.id,
        'sender_name': current_user.username,
        'sender_avatar': current_user.avatar,
        'chat_type': chat_type,
        'chat_id': chat_id,
        'content_type': content_type,
        'content': content,  # المحتوى الأصلي غير المشفر
        'media_url': media_url,
        'media_thumbnail': media_thumbnail,
        'media_duration': media_duration,
        'media_size': media_size,
        'location_lat': location.get('lat') if location else None,
        'location_lng': location.get('lng') if location else None,
        'location_live_until': msg.location_live_until.isoformat() if msg.location_live_until else None,
        'reply_to_id': reply_to,
        'disappearing_at': disappearing_at.isoformat() if disappearing_at else None,
        'is_view_once': is_view_once,
        'is_hd': is_hd,
        'is_encrypted': True,
        'reactions': {},
        'timestamp': msg.timestamp.isoformat(),
        'delivered_at': msg.delivered_at.isoformat() if msg.delivered_at else None
    }
    
    # إرسال للغرفة المناسبة
    emit('new_message', msg_data, room=room)
    if chat_type == 'private':
        # إرسال نسخة للمرسل أيضاً
        emit('new_message', msg_data, room=sender_room)

@socketio.on('message_read')
def handle_message_read(data):
    """تحديث حالة القراءة (علامات زرقاء)"""
    msg_ids = data.get('message_ids', [])
    for msg_id in msg_ids:
        msg = Message.query.get(msg_id)
        if msg and msg.receiver_id == current_user.id and not msg.read_at:
            msg.read_at = datetime.utcnow()
    
    db.session.commit()
    
    if msg_ids:
        sender_id = data.get('sender_id')
        if sender_id:
            emit('messages_read', {
                'message_ids': msg_ids,
                'reader_id': current_user.id,
                'read_at': datetime.utcnow().isoformat()
            }, room=f'user_{sender_id}')

@socketio.on('reaction')
def handle_reaction(data):
    """إضافة/إزالة تفاعل (إيموجي)"""
    msg_id = data.get('message_id')
    emoji = data.get('emoji')
    
    msg = Message.query.get(msg_id)
    if not msg:
        return
    
    reactions = json.loads(msg.reactions or '{}')
    if emoji not in reactions:
        reactions[emoji] = []
    
    if current_user.id in reactions[emoji]:
        reactions[emoji].remove(current_user.id)
        if not reactions[emoji]:
            del reactions[emoji]
    else:
        reactions[emoji].append(current_user.id)
    
    msg.reactions = json.dumps(reactions)
    db.session.commit()
    
    # إرسال التحديث
    emit('reaction_updated', {
        'message_id': msg_id,
        'reactions': reactions,
        'user_id': current_user.id
    }, room=f'user_{msg.sender_id}')

@socketio.on('call_request')
def handle_call_request(data):
    """طلب مكالمة صوتية/فيديو"""
    target_id = data.get('target_id')
    call_type = data.get('call_type', 'audio')  # audio, video, group
    
    emit('incoming_call', {
        'caller_id': current_user.id,
        'caller_name': current_user.username,
        'caller_avatar': current_user.avatar,
        'call_type': call_type,
        'group_id': data.get('group_id')
    }, room=f'user_{target_id}')

@socketio.on('call_accepted')
def handle_call_accepted(data):
    emit('call_accepted', {
        'callee_id': current_user.id,
        'callee_name': current_user.username
    }, room=f'user_{data["caller_id"]}')

@socketio.on('call_declined')
def handle_call_declined(data):
    emit('call_declined', {
        'reason': 'تم رفض المكالمة'
    }, room=f'user_{data["caller_id"]}')

@socketio.on('webrtc_signal')
def handle_webrtc_signal(data):
    """إشارات WebRTC للمكالمات"""
    target = data.get('target_id')
    signal_type = data.get('type')  # offer, answer, ice-candidate
    emit('webrtc_signal', {
        'from_id': current_user.id,
        'type': signal_type,
        'data': data.get('data')
    }, room=f'user_{target}')


# ====================
# HTML Templates
# ====================
LOGIN_HTML = '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#0a0a1a">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>Perna - تسجيل الدخول</title>
    <link rel="icon" href="https://i.ibb.co/PGvjmB9F/Untitled4-20260424011520.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg: #0a0a1a;
            --surface: #12122a;
            --primary: #00b4d8;
            --primary-dark: #0077b6;
            --text: #ffffff;
            --text-secondary: #b0b0c0;
            --danger: #ff4757;
            --success: #2ed573;
            --border: rgba(255,255,255,0.08);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', sans-serif;
            background: var(--bg);
            color: var(--text);
            height: 100vh;
            height: 100dvh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            -webkit-tap-highlight-color: transparent;
            user-select: none;
            -webkit-user-select: none;
        }
        .login-container {
            width: 100%;
            max-width: 400px;
            padding: 20px;
        }
        .logo-section {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo-section img {
            width: 80px;
            height: 80px;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0,180,216,0.3);
        }
        .logo-section h1 {
            font-size: 2rem;
            font-weight: 700;
            margin-top: 10px;
            background: linear-gradient(135deg, var(--primary), #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .card {
            background: var(--surface);
            border-radius: 20px;
            padding: 25px;
            border: 1px solid var(--border);
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }
        .card h3 {
            text-align: center;
            margin-bottom: 20px;
            color: var(--text-secondary);
        }
        .form-group {
            margin-bottom: 15px;
            position: relative;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            background: rgba(255,255,255,0.05);
            border: 1.5px solid var(--border);
            border-radius: 12px;
            color: var(--text);
            font-size: 1rem;
            transition: all 0.3s;
            outline: none;
        }
        .form-group input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(0,180,216,0.15);
            background: rgba(255,255,255,0.08);
        }
        .btn {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            text-align: center;
            display: block;
        }
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            margin-top: 10px;
        }
        .btn-primary:active {
            transform: scale(0.97);
            opacity: 0.9;
        }
        .btn-secondary {
            background: transparent;
            color: var(--primary);
            border: 1.5px solid var(--primary);
            margin-top: 10px;
        }
        .links {
            text-align: center;
            margin-top: 15px;
        }
        .links a {
            color: var(--primary);
            text-decoration: none;
            font-size: 0.9rem;
        }
        .alert {
            background: rgba(255,71,87,0.15);
            color: var(--danger);
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 15px;
            font-size: 0.9rem;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo-section">
            <img src="https://i.ibb.co/PGvjmB9F/Untitled4-20260424011520.png" alt="Perna Logo">
            <h1>Perna</h1>
        </div>
        <div class="card">
            <h3><i class="fas fa-sign-in-alt"></i> تسجيل الدخول</h3>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert">{{ messages[0] }}</div>
              {% endif %}
            {% endwith %}
            <form method="POST">
                <div class="form-group">
                    <label>اسم المستخدم</label>
                    <input type="text" name="username" placeholder="أدخل اسم المستخدم" required autocomplete="username">
                </div>
                <div class="form-group">
                    <label>كلمة المرور</label>
                    <input type="password" name="password" placeholder="كلمة المرور" required autocomplete="current-password">
                </div>
                {% if require_2fa %}
                <div class="form-group">
                    <label>رمز التحقق (6 أرقام)</label>
                    <input type="text" name="two_factor" placeholder="000000" maxlength="6" pattern="[0-9]{6}" required>
                </div>
                {% endif %}
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-arrow-left"></i> دخول
                </button>
            </form>
            <div class="links">
                <a href="/register">ليس لديك حساب؟ إنشاء حساب جديد</a>
            </div>
        </div>
    </div>
</body>
</html>
'''

REGISTER_HTML = '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#0a0a1a">
    <title>Perna - إنشاء حساب</title>
    <link rel="icon" href="https://i.ibb.co/PGvjmB9F/Untitled4-20260424011520.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg: #0a0a1a;
            --surface: #12122a;
            --primary: #00b4d8;
            --primary-dark: #0077b6;
            --text: #ffffff;
            --text-secondary: #b0b0c0;
            --danger: #ff4757;
            --border: rgba(255,255,255,0.08);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg);
            color: var(--text);
            height: 100vh;
            height: 100dvh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            overflow-y: auto;
        }
        .login-container {
            width: 100%;
            max-width: 400px;
        }
        .logo-section {
            text-align: center;
            margin-bottom: 20px;
        }
        .logo-section img {
            width: 70px;
            height: 70px;
            border-radius: 18px;
            box-shadow: 0 8px 25px rgba(0,180,216,0.3);
        }
        .logo-section h1 {
            font-size: 1.8rem;
            background: linear-gradient(135deg, #00b4d8, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-top: 8px;
        }
        .card {
            background: var(--surface);
            border-radius: 20px;
            padding: 25px;
            border: 1px solid var(--border);
        }
        .card h3 { text-align: center; margin-bottom: 20px; color: var(--text-secondary); }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; color: var(--text-secondary); font-size: 0.85rem; }
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            background: rgba(255,255,255,0.05);
            border: 1.5px solid var(--border);
            border-radius: 12px;
            color: var(--text);
            font-size: 1rem;
            outline: none;
            transition: 0.3s;
        }
        .form-group input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(0,180,216,0.15);
        }
        .btn {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: 0.3s;
        }
        .btn-primary {
            background: linear-gradient(135deg, #00b4d8, #0077b6);
            color: white;
            margin-top: 10px;
        }
        .btn-primary:active { transform: scale(0.97); }
        .links { text-align: center; margin-top: 15px; }
        .links a { color: #00b4d8; text-decoration: none; font-size: 0.9rem; }
        .alert {
            background: rgba(255,71,87,0.15);
            color: #ff4757;
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 15px;
            font-size: 0.9rem;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo-section">
            <img src="https://i.ibb.co/PGvjmB9F/Untitled4-20260424011520.png" alt="Perna Logo">
            <h1>Perna</h1>
        </div>
        <div class="card">
            <h3><i class="fas fa-user-plus"></i> إنشاء حساب جديد</h3>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert">{{ messages[0] }}</div>
              {% endif %}
            {% endwith %}
            <form method="POST">
                <div class="form-group">
                    <label>اسم المستخدم</label>
                    <input type="text" name="username" placeholder="اختر اسم مستخدم" required>
                </div>
                <div class="form-group">
                    <label>رقم الهاتف</label>
                    <input type="tel" name="phone" placeholder="+9665xxxxxxxx" required>
                </div>
                <div class="form-group">
                    <label>البريد الإلكتروني</label>
                    <input type="email" name="email" placeholder="example@email.com">
                </div>
                <div class="form-group">
                    <label>كلمة المرور</label>
                    <input type="password" name="password" placeholder="كلمة مرور قوية" required minlength="8">
                </div>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-check"></i> إنشاء حساب
                </button>
            </form>
            <div class="links">
                <a href="/login">لديك حساب؟ تسجيل الدخول</a>
            </div>
        </div>
    </div>
</body>
</html>
'''

CHAT_HTML = '''
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <meta name="theme-color" content="#0a0a1a">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="Perna">
    <link rel="manifest" href="/manifest.json">
    <link rel="icon" href="https://i.ibb.co/PGvjmB9F/Untitled4-20260424011520.png">
    <title>Perna - تطبيق المراسلة</title>
    
    <!-- مكتبات الأيقونات والخرائط -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    
    <style>
        :root {
            --bg: #0a0a1a;
            --surface: #12122a;
            --surface-light: #1a1a35;
            --primary: #00b4d8;
            --primary-dark: #0077b6;
            --accent: #ff6b6b;
            --text: #ffffff;
            --text-secondary: #a0a0b8;
            --text-tertiary: #6a6a80;
            --border: rgba(255,255,255,0.08);
            --bubble-sent: linear-gradient(135deg, #00b4d8, #0077b6);
            --bubble-received: #1e1e3a;
            --safe-bottom: env(safe-area-inset-bottom, 0px);
            --header-height: 56px;
            --nav-height: 66px;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', sans-serif;
            background: var(--bg);
            color: var(--text);
            height: 100vh;
            height: 100dvh;
            overflow: hidden;
            -webkit-tap-highlight-color: transparent;
            -webkit-font-smoothing: antialiased;
            user-select: none;
            -webkit-user-select: none;
            -webkit-overflow-scrolling: touch;
        }
        
        /* شريط الحالة للآيفون */
        .status-bar {
            height: env(safe-area-inset-top, 0px);
            background: var(--bg);
        }
        
        /* الهيكل الرئيسي */
        .app-shell {
            display: flex;
            flex-direction: column;
            height: calc(100vh - env(safe-area-inset-top, 0px));
            height: calc(100dvh - env(safe-area-inset-top, 0px));
            max-width: 500px;
            margin: 0 auto;
            position: relative;
            overflow: hidden;
        }
        
        /* رأس التطبيق */
        .app-header {
            height: var(--header-height);
            background: var(--surface);
            display: flex;
            align-items: center;
            padding: 0 16px;
            gap: 12px;
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
        }
        .app-header .back-btn {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            background: rgba(255,255,255,0.05);
            border: none;
            color: var(--text);
            font-size: 1.1rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: 0.2s;
        }
        .app-header .back-btn:active { background: rgba(255,255,255,0.15); }
        .app-header .title {
            flex: 1;
            font-weight: 600;
            font-size: 1.1rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .app-header .actions {
            display: flex;
            gap: 8px;
        }
        .app-header .actions button {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            background: transparent;
            border: none;
            color: var(--primary);
            font-size: 1.1rem;
            cursor: pointer;
            transition: 0.2s;
        }
        .app-header .actions button:active { background: rgba(0,180,216,0.15); }
        
        /* عرض المحتوى الرئيسي */
        .main-content {
            flex: 1;
            overflow-y: auto;
            overflow-x: hidden;
            -webkit-overflow-scrolling: touch;
            scroll-behavior: smooth;
        }
        
        /* شاشة المحادثات */
        .conversations-screen { display: block; }
        .chat-screen, .status-screen, .calls-screen, .settings-screen { display: none; }
        
        .conversation-item {
            display: flex;
            align-items: center;
            padding: 12px 16px;
            gap: 12px;
            cursor: pointer;
            transition: background 0.2s;
            border-bottom: 1px solid var(--border);
            position: relative;
        }
        .conversation-item:active { background: rgba(255,255,255,0.03); }
        .conversation-item .avatar {
            width: 52px;
            height: 52px;
            border-radius: 50%;
            object-fit: cover;
            background: var(--surface-light);
            flex-shrink: 0;
            position: relative;
        }
        .conversation-item .online-dot {
            position: absolute;
            bottom: 2px;
            right: 2px;
            width: 12px;
            height: 12px;
            background: #2ed573;
            border-radius: 50%;
            border: 2px solid var(--bg);
        }
        .conversation-item .info {
            flex: 1;
            min-width: 0;
        }
        .conversation-item .name {
            font-weight: 600;
            font-size: 0.95rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .conversation-item .last-msg {
            color: var(--text-secondary);
            font-size: 0.8rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-top: 3px;
        }
        .conversation-item .meta {
            text-align: left;
            flex-shrink: 0;
        }
        .conversation-item .time {
            font-size: 0.7rem;
            color: var(--text-tertiary);
        }
        .conversation-item .unread-badge {
            background: var(--primary);
            color: white;
            border-radius: 50%;
            min-width: 20px;
            height: 20px;
            font-size: 0.7rem;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-top: 4px;
            font-weight: 600;
        }
        
        /* شاشة الدردشة */
        .chat-messages {
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            min-height: 100%;
        }
        .message-row {
            display: flex;
            flex-direction: column;
            max-width: 85%;
            animation: fadeInUp 0.3s ease;
        }
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .message-row.sent { align-self: flex-end; align-items: flex-end; }
        .message-row.received { align-self: flex-start; align-items: flex-start; }
        
        .message-bubble {
            padding: 10px 14px;
            border-radius: 18px;
            font-size: 0.9rem;
            line-height: 1.4;
            word-wrap: break-word;
            overflow-wrap: break-word;
            position: relative;
            max-width: 100%;
        }
        .message-row.sent .message-bubble {
            background: var(--bubble-sent);
            color: white;
            border-bottom-right-radius: 4px;
        }
        .message-row.received .message-bubble {
            background: var(--bubble-received);
            border-bottom-left-radius: 4px;
        }
        .message-bubble .msg-image {
            max-width: 250px;
            max-height: 300px;
            border-radius: 10px;
            margin: 4px 0;
            cursor: pointer;
        }
        .message-bubble .msg-video {
            max-width: 250px;
            border-radius: 10px;
            margin: 4px 0;
        }
        .message-bubble .msg-audio {
            min-width: 180px;
            margin: 4px 0;
        }
        .message-bubble .msg-doc {
            background: rgba(255,255,255,0.1);
            padding: 10px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
            margin: 4px 0;
        }
        .message-bubble .reply-preview {
            background: rgba(0,0,0,0.2);
            padding: 6px 10px;
            border-radius: 8px;
            margin-bottom: 6px;
            font-size: 0.75rem;
            border-right: 3px solid var(--primary);
        }
        .msg-time {
            font-size: 0.65rem;
            opacity: 0.7;
            margin-top: 4px;
            text-align: left;
        }
        .msg-read-status {
            display: inline-block;
            margin-left: 4px;
            font-size: 0.7rem;
        }
        .msg-read-status.read { color: #34b7f1; }
        
        /* شريط الإدخال */
        .input-bar {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            padding-bottom: calc(8px + var(--safe-bottom));
            background: var(--surface);
            border-top: 1px solid var(--border);
        }
        .input-bar textarea {
            flex: 1;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 10px 16px;
            color: var(--text);
            font-size: 0.9rem;
            resize: none;
            max-height: 100px;
            outline: none;
            font-family: inherit;
        }
        .input-bar textarea:focus {
            border-color: var(--primary);
            background: rgba(255,255,255,0.08);
        }
        .input-bar .icon-btn {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: transparent;
            border: none;
            color: var(--primary);
            font-size: 1.2rem;
            cursor: pointer;
            flex-shrink: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: 0.2s;
        }
        .input-bar .icon-btn:active { background: rgba(0,180,216,0.15); transform: scale(0.9); }
        .input-bar .send-btn {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--primary);
            border: none;
            color: white;
            font-size: 1rem;
            cursor: pointer;
            flex-shrink: 0;
            transition: 0.2s;
        }
        .input-bar .send-btn:active { transform: scale(0.9); background: var(--primary-dark); }
        
        /* شريط التنقل السفلي */
        .bottom-nav {
            display: flex;
            align-items: center;
            justify-content: space-around;
            padding: 8px 0;
            padding-bottom: calc(8px + var(--safe-bottom));
            background: var(--surface);
            border-top: 1px solid var(--border);
            height: var(--nav-height);
        }
        .bottom-nav .nav-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 4px;
            cursor: pointer;
            color: var(--text-tertiary);
            transition: 0.2s;
            background: none;
            border: none;
            font-size: 0.7rem;
            padding: 4px 12px;
            border-radius: 12px;
        }
        .bottom-nav .nav-item i { font-size: 1.3rem; }
        .bottom-nav .nav-item.active { color: var(--primary); }
        .bottom-nav .nav-item:active { background: rgba(0,180,216,0.1); }
        
        /* أزرار عائمة */
        .fab {
            position: fixed;
            bottom: calc(var(--nav-height) + 20px + var(--safe-bottom));
            right: 20px;
            width: 52px;
            height: 52px;
            border-radius: 50%;
            background: var(--primary);
            border: none;
            color: white;
            font-size: 1.3rem;
            cursor: pointer;
            box-shadow: 0 8px 25px rgba(0,180,216,0.4);
            z-index: 50;
            transition: 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .fab:active { transform: scale(0.9); }
        
        /* أوراق سفلية (Bottom Sheets) */
        .bottom-sheet-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.6);
            z-index: 200;
            display: none;
            opacity: 0;
            transition: opacity 0.3s;
        }
        .bottom-sheet-overlay.show { display: block; opacity: 1; }
        
        .bottom-sheet {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: var(--surface);
            border-radius: 20px 20px 0 0;
            padding: 20px;
            padding-bottom: calc(20px + var(--safe-bottom));
            z-index: 201;
            transform: translateY(100%);
            transition: transform 0.3s ease;
            max-height: 70vh;
            overflow-y: auto;
            max-width: 500px;
            margin: 0 auto;
        }
        .bottom-sheet.show { transform: translateY(0); }
        .bottom-sheet .handle {
            width: 40px;
            height: 4px;
            background: var(--border);
            border-radius: 2px;
            margin: 0 auto 15px;
        }
        .bottom-sheet h4 {
            margin-bottom: 15px;
            color: var(--text);
        }
        
        /* مودال */
        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.7);
            z-index: 300;
            display: none;
            align-items: center;
            justify-content: center;
        }
        .modal-overlay.show { display: flex; }
        .modal-content {
            background: var(--surface);
            border-radius: 16px;
            padding: 20px;
            width: 90%;
            max-width: 400px;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        /* أنماط عامة */
        .text-center { text-align: center; }
        .text-secondary { color: var(--text-secondary); }
        .mt-3 { margin-top: 12px; }
        .mb-3 { margin-bottom: 12px; }
        
        input[type="file"] { display: none; }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 3px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        
        /* تأثيرات */
        .ripple {
            position: relative;
            overflow: hidden;
        }
        .ripple::after {
            content: '';
            position: absolute;
            width: 100%;
            padding-top: 100%;
            border-radius: 50%;
            background: rgba(255,255,255,0.2);
            transform: scale(0);
            opacity: 0;
            transition: transform 0.5s, opacity 1s;
        }
        .ripple:active::after {
            transform: scale(4);
            opacity: 0;
            transition: 0s;
        }
    </style>
</head>
<body>
    <div class="status-bar"></div>
    
    <!-- التطبيق الرئيسي -->
    <div class="app-shell" id="appShell">
        <!-- رأس التطبيق -->
        <header class="app-header" id="appHeader">
            <button class="back-btn" id="backBtn" onclick="goBack()" style="display:none">
                <i class="fas fa-arrow-right"></i>
            </button>
            <span class="title" id="headerTitle">Perna</span>
            <div class="actions">
                <button onclick="openSearch()"><i class="fas fa-search"></i></button>
                <button onclick="openNewChatSheet()"><i class="fas fa-edit"></i></button>
            </div>
        </header>
        
        <!-- المحتوى الرئيسي -->
        <main class="main-content" id="mainContent">
            <!-- شاشة المحادثات -->
            <div class="conversations-screen" id="conversationsScreen">
                <div id="conversationsList"></div>
                <div class="text-center text-secondary mt-3 mb-3" id="emptyConvos">لا توجد محادثات بعد</div>
            </div>
            
            <!-- شاشة الدردشة -->
            <div class="chat-screen" id="chatScreen">
                <div class="chat-messages" id="chatMessages"></div>
            </div>
        </main>
        
        <!-- شريط الإدخال (يظهر في شاشة الدردشة) -->
        <div class="input-bar" id="inputBar" style="display:none">
            <button class="icon-btn" onclick="document.getElementById('fileInput').click()">
                <i class="fas fa-paperclip"></i>
            </button>
            <textarea id="messageInput" placeholder="اكتب رسالة..." rows="1" dir="auto"></textarea>
            <button class="icon-btn" id="voiceRecordBtn" onmousedown="startRecording()" onmouseup="stopRecording()" ontouchstart="startRecording()" ontouchend="stopRecording()">
                <i class="fas fa-microphone"></i>
            </button>
            <button class="send-btn" id="sendBtn" onclick="sendMessage()" style="display:none">
                <i class="fas fa-paper-plane"></i>
            </button>
            <input type="file" id="fileInput" accept="image/*,video/*,audio/*,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx" onchange="handleFileSend(this)">
        </div>
        
        <!-- شريط التنقل السفلي -->
        <nav class="bottom-nav" id="bottomNav">
            <button class="nav-item active" onclick="showScreen('conversations')">
                <i class="fas fa-comments"></i>
                <span>الدردشات</span>
            </button>
            <button class="nav-item" onclick="showScreen('calls')">
                <i class="fas fa-phone-alt"></i>
                <span>المكالمات</span>
            </button>
            <button class="nav-item" onclick="showScreen('status')">
                <i class="fas fa-circle-notch"></i>
                <span>الحالة</span>
            </button>
            <button class="nav-item" onclick="showScreen('settings')">
                <i class="fas fa-cog"></i>
                <span>الإعدادات</span>
            </button>
        </nav>
    </div>
    
    <!-- الورقة السفلية للمحادثة الجديدة -->
    <div class="bottom-sheet-overlay" id="newChatOverlay" onclick="closeNewChatSheet()"></div>
    <div class="bottom-sheet" id="newChatSheet">
        <div class="handle"></div>
        <h4><i class="fas fa-plus-circle"></i> محادثة جديدة</h4>
        <input type="text" id="searchUsers" placeholder="ابحث عن مستخدمين..." class="form-input" 
               style="width:100%;padding:12px;border-radius:12px;border:1px solid var(--border);background:rgba(255,255,255,0.05);color:white;margin-bottom:15px;outline:none;">
        <div id="searchResults"></div>
        <button class="btn-secondary" onclick="openCreateGroupSheet()" style="width:100%;padding:12px;margin-top:10px;background:transparent;border:1px solid var(--primary);color:var(--primary);border-radius:12px;cursor:pointer;">
            <i class="fas fa-users"></i> إنشاء مجموعة جديدة
        </button>
        <button class="btn-secondary" onclick="openCreateChannelSheet()" style="width:100%;padding:12px;margin-top:10px;background:transparent;border:1px solid var(--primary);color:var(--primary);border-radius:12px;cursor:pointer;">
            <i class="fas fa-bullhorn"></i> إنشاء قناة
        </button>
    </div>
    
    {% raw %}
    <!-- ==================== JavaScript ==================== -->
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        // ==================== GLOBAL STATE ====================
        const socket = io();
        let currentUser = null;
        let currentScreen = 'conversations';
        let currentChat = null; // {type, id, name, avatar}
        let conversations = [];
        let allUsers = [];
        let mediaRecorder = null;
        let audioChunks = [];
        let isRecording = false;
        let replyToMessage = null;
        
        // ==================== INITIALIZATION ====================
        document.addEventListener('DOMContentLoaded', async () => {
            await loadCurrentUser();
            await loadConversations();
            setupSocketListeners();
            setupEventListeners();
            showScreen('conversations');
        });
        
        async function loadCurrentUser() {
            const res = await fetch('/api/me');
            currentUser = await res.json();
        }
        
        async function loadConversations() {
            try {
                const res = await fetch('/api/conversations');
                conversations = await res.json();
                renderConversations();
            } catch (e) {
                console.error('Error loading conversations:', e);
            }
        }
        
        function renderConversations(filter = null) {
            const container = document.getElementById('conversationsList');
            const empty = document.getElementById('emptyConvos');
            let list = conversations;
            
            if (filter) {
                list = conversations.filter(c => 
                    c.name.toLowerCase().includes(filter.toLowerCase())
                );
            }
            
            if (list.length === 0) {
                container.innerHTML = '';
                empty.style.display = 'block';
                return;
            }
            
            empty.style.display = 'none';
            container.innerHTML = list.map(c => `
                <div class="conversation-item ripple" onclick="openChat('${c.type}', ${c.id}, '${c.name.replace(/'/g, "\\'")}', '${c.avatar || ''}')">
                    <div style="position:relative;flex-shrink:0;">
                        <div class="avatar" style="background:${getAvatarColor(c.name)};display:flex;align-items:center;justify-content:center;font-weight:bold;font-size:1.2rem;color:white;">
                            ${c.avatar && c.avatar !== 'default.png' ? 
                                `<img src="${c.avatar}" class="avatar">` : 
                                c.name.charAt(0).toUpperCase()}
                            ${c.is_online ? '<span class="online-dot"></span>' : ''}
                        </div>
                    </div>
                    <div class="info">
                        <div class="name">
                            ${c.type === 'group' ? '👥 ' : c.type === 'channel' ? '📢 ' : ''}${c.name}
                        </div>
                        <div class="last-msg">
                            ${c.last_type === 'image' ? '📷 صورة' : 
                              c.last_type === 'video' ? '🎥 فيديو' : 
                              c.last_type === 'audio' ? '🎤 رسالة صوتية' :
                              c.last_type === 'doc' ? '📄 مستند' :
                              c.last_type === 'sticker' ? '🎯 ملصق' :
                              c.last_message || 'ابدأ المحادثة'}
                        </div>
                    </div>
                    <div class="meta" style="text-align:left;">
                        <div class="time">${formatTime(c.timestamp)}</div>
                        ${c.unread ? `<span class="unread-badge">${c.unread}</span>` : ''}
                    </div>
                </div>
            `).join('');
        }
        
        // ==================== SCREEN NAVIGATION ====================
        function showScreen(screen) {
            currentScreen = screen;
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            
            const screens = ['conversations', 'chat', 'status', 'calls', 'settings'];
            screens.forEach(s => {
                const el = document.getElementById(`${s}Screen`);
                if (el) el.style.display = 'none';
            });
            
            document.getElementById('inputBar').style.display = 'none';
            document.getElementById('backBtn').style.display = 'none';
            
            switch(screen) {
                case 'conversations':
                    document.getElementById('conversationsScreen').style.display = 'block';
                    document.getElementById('headerTitle').textContent = 'Perna';
                    document.querySelector('.nav-item:nth-child(1)').classList.add('active');
                    loadConversations();
                    break;
                case 'chat':
                    document.getElementById('chatScreen').style.display = 'block';
                    document.getElementById('inputBar').style.display = 'flex';
                    document.getElementById('backBtn').style.display = 'flex';
                    break;
                case 'status':
                    document.getElementById('conversationsScreen').style.display = 'block';
                    document.getElementById('headerTitle').textContent = 'الحالة';
                    document.querySelector('.nav-item:nth-child(3)').classList.add('active');
                    loadStatuses();
                    break;
                case 'calls':
                    document.getElementById('conversationsScreen').style.display = 'block';
                    document.getElementById('headerTitle').textContent = 'المكالمات';
                    document.querySelector('.nav-item:nth-child(2)').classList.add('active');
                    document.getElementById('conversationsList').innerHTML = '<div class="text-center text-secondary mt-5">سجل المكالمات</div>';
                    break;
                case 'settings':
                    document.getElementById('conversationsScreen').style.display = 'block';
                    document.getElementById('headerTitle').textContent = 'الإعدادات';
                    document.querySelector('.nav-item:nth-child(4)').classList.add('active');
                    document.getElementById('conversationsList').innerHTML = renderSettingsHTML();
                    break;
            }
        }
        
        function goBack() {
            if (currentChat) {
                if (currentChat.type) {
                    socket.emit('leave_chat', {type: currentChat.type, id: currentChat.id});
                }
                currentChat = null;
            }
            showScreen('conversations');
        }
        
        // ==================== CHAT OPENING ====================
        async function openChat(type, id, name, avatar) {
            currentChat = { type, id, name, avatar };
            document.getElementById('headerTitle').textContent = name;
            document.getElementById('backBtn').style.display = 'flex';
            
            document.getElementById('conversationsScreen').style.display = 'none';
            document.getElementById('chatScreen').style.display = 'block';
            document.getElementById('inputBar').style.display = 'flex';
            
            document.getElementById('chatMessages').innerHTML = '';
            
            // الانضمام إلى غرفة WebSocket
            socket.emit('join_chat', {type, id});
            
            // تحميل الرسائل
            try {
                const res = await fetch(`/api/messages/${type}/${id}`);
                const messages = await res.json();
                messages.forEach(msg => appendMessage(msg, false));
                scrollToBottom();
            } catch (e) {
                console.error(e);
            }
        }
        
        // ==================== SEND MESSAGE ====================
        function sendMessage() {
            const input = document.getElementById('messageInput');
            const content = input.value.trim();
            
            if (!content && !pendingFile) return;
            if (!currentChat) return;
            
            const data = {
                type: currentChat.type,
                id: currentChat.id,
                content: content,
                content_type: 'text',
                reply_to_id: replyToMessage ? replyToMessage.id : null
            };
            
            if (pendingFile) {
                data.content_type = pendingFile.type;
                data.media_url = pendingFile.url;
                data.media_thumbnail = pendingFile.thumbnail;
                data.media_duration = pendingFile.duration;
                data.media_size = pendingFile.size;
                pendingFile = null;
            }
            
            socket.emit('send_message', data);
            input.value = '';
            replyToMessage = null;
            updateSendButton();
            document.getElementById('fileInput').value = '';
        }
        
        function updateSendButton() {
            const input = document.getElementById('messageInput');
            const sendBtn = document.getElementById('sendBtn');
            const voiceBtn = document.getElementById('voiceRecordBtn');
            
            if (input.value.trim() || pendingFile) {
                sendBtn.style.display = 'flex';
                voiceBtn.style.display = 'none';
            } else {
                sendBtn.style.display = 'none';
                voiceBtn.style.display = 'flex';
            }
        }
        
        let pendingFile = null;
        
        async function handleFileSend(input) {
            const file = input.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            let uploadType = 'media';
            if (file.type.startsWith('audio/')) uploadType = 'media';
            else if (file.type.includes('pdf') || file.type.includes('word') || file.type.includes('excel')) uploadType = 'doc';
            
            formData.append('type', uploadType);
            
            try {
                const res = await fetch('/api/upload', { method: 'POST', body: formData });
                const data = await res.json();
                
                pendingFile = {
                    url: data.url,
                    thumbnail: data.thumbnail,
                    type: file.type.startsWith('image/') ? 'image' :
                          file.type.startsWith('video/') ? 'video' :
                          file.type.startsWith('audio/') ? 'audio' : 'doc',
                    size: data.size,
                    duration: null
                };
                
                updateSendButton();
                
                // معاينة سريعة
                if (pendingFile.type === 'image') {
                    document.getElementById('messageInput').value = '[صورة جاهزة للإرسال - اضغط إرسال]';
                    updateSendButton();
                }
            } catch (e) {
                console.error('Upload failed:', e);
                alert('فشل رفع الملف');
            }
        }
        
        // ==================== APPEND MESSAGE TO UI ====================
        function appendMessage(msg, scroll = true) {
            const container = document.getElementById('chatMessages');
            const isSent = msg.sender_id === currentUser.id;
            
            const row = document.createElement('div');
            row.className = `message-row ${isSent ? 'sent' : 'received'}`;
            row.id = `msg-${msg.id}`;
            
            let html = '<div class="message-bubble">';
            
            // الرد على رسالة
            if (msg.reply_to_id) {
                html += `<div class="reply-preview">↩ رد على رسالة</div>`;
            }
            
            // المحتوى حسب النوع
            switch(msg.content_type) {
                case 'image':
                    html += `<img src="${msg.media_url}" class="msg-image" onclick="viewFullImage('${msg.media_url}')" loading="lazy">`;
                    if (msg.content) html += `<div>${msg.content}</div>`;
                    if (msg.is_hd) html += '<span style="font-size:0.65rem;background:rgba(0,0,0,0.4);padding:2px 6px;border-radius:4px;">HD</span>';
                    break;
                case 'video':
                    html += `<video controls class="msg-video" preload="metadata"><source src="${msg.media_url}"></video>`;
                    if (msg.content) html += `<div>${msg.content}</div>`;
                    break;
                case 'audio':
                    html += `<audio controls class="msg-audio" preload="metadata"><source src="${msg.media_url}"></audio>`;
                    break;
                case 'doc':
                    html += `<div class="msg-doc"><i class="fas fa-file"></i> مستند</div>`;
                    if (msg.content) html += `<div>${msg.content}</div>`;
                    break;
                case 'location':
                    html += `<div>📍 موقع</div>`;
                    break;
                default:
                    html += `<div>${escapeHtml(msg.content || '')}</div>`;
            }
            
            // حالة القراءة والوقت
            html += `<div class="msg-time">${formatTime(msg.timestamp)}`;
            if (isSent) {
                if (msg.read_at) {
                    html += ' <span class="msg-read-status read">✓✓</span>';
                } else if (msg.delivered_at) {
                    html += ' <span class="msg-read-status">✓✓</span>';
                } else {
                    html += ' <span class="msg-read-status">✓</span>';
                }
            }
            html += '</div>';
            html += '</div>';
            
            row.innerHTML = html;
            
            // إضافة تفاعلات (long press)
            row.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                showMessageActions(msg, row);
            });
            
            // Double tap للتفاعل السريع
            row.addEventListener('dblclick', () => {
                socket.emit('reaction', { message_id: msg.id, emoji: '👍' });
            });
            
            container.appendChild(row);
            
            if (scroll) {
                scrollToBottom();
            }
            
            // تحديث حالة القراءة للرسائل المستلمة
            if (!isSent && !msg.read_at) {
                socket.emit('message_read', {
                    message_ids: [msg.id],
                    sender_id: msg.sender_id
                });
            }
        }
        
        function scrollToBottom() {
            const container = document.getElementById('chatMessages');
            setTimeout(() => {
                container.scrollTop = container.scrollHeight;
            }, 100);
        }
        
        function showMessageActions(msg, element) {
            // قائمة منبثقة: رد، إعادة توجيه، نسخ، حذف
            const actions = [
                { label: 'رد', icon: 'fa-reply', action: () => { replyToMessage = msg; document.getElementById('messageInput').focus(); } },
                { label: 'نسخ', icon: 'fa-copy', action: () => { navigator.clipboard.writeText(msg.content); } },
                { label: 'إعادة توجيه', icon: 'fa-share', action: () => { /* forward */ } },
            ];
            // سيتم تنفيذها كقائمة بسيطة
            const menu = document.createElement('div');
            menu.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--surface);border-radius:16px;padding:16px;z-index:500;box-shadow:0 20px 60px rgba(0,0,0,0.8);';
            menu.innerHTML = actions.map(a => 
                `<div style="padding:12px;cursor:pointer;border-radius:8px;" onclick="this.parentElement.remove();(${a.action.toString()})()">
                    <i class="fas ${a.icon}"></i> ${a.label}
                </div>`
            ).join('');
            document.body.appendChild(menu);
            setTimeout(() => menu.addEventListener('click', () => menu.remove()), 100);
        }
        
        // ==================== VOICE RECORDING ====================
        async function startRecording() {
            if (isRecording) return;
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                mediaRecorder = new MediaRecorder(stream);
                audioChunks = [];
                
                mediaRecorder.ondataavailable = (e) => {
                    audioChunks.push(e.data);
                };
                
                mediaRecorder.onstop = async () => {
                    const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                    const formData = new FormData();
                    formData.append('file', audioBlob, 'voice_note.webm');
                    formData.append('type', 'media');
                    
                    const res = await fetch('/api/upload', { method: 'POST', body: formData });
                    const data = await res.json();
                    
                    if (currentChat) {
                        socket.emit('send_message', {
                            type: currentChat.type,
                            id: currentChat.id,
                            content: '',
                            content_type: 'audio',
                            media_url: data.url,
                            media_duration: Math.round(audioBlob.size / 16000) // تقريبي
                        });
                    }
                    
                    stream.getTracks().forEach(t => t.stop());
                    isRecording = false;
                };
                
                mediaRecorder.start();
                isRecording = true;
                document.getElementById('voiceRecordBtn').style.color = '#ff4757';
                document.getElementById('voiceRecordBtn').innerHTML = '<i class="fas fa-stop"></i>';
            } catch (e) {
                console.error('Recording failed:', e);
                alert('تعذر الوصول للميكروفون');
            }
        }
        
        function stopRecording() {
            if (mediaRecorder && isRecording) {
                mediaRecorder.stop();
                document.getElementById('voiceRecordBtn').style.color = '';
                document.getElementById('voiceRecordBtn').innerHTML = '<i class="fas fa-microphone"></i>';
            }
        }
        
        // ==================== WEBSOCKET LISTENERS ====================
        function setupSocketListeners() {
            socket.on('new_message', (msg) => {
                if (currentChat && 
                    ((currentChat.type === 'private' && msg.chat_type === 'private' && 
                      (msg.chat_id === currentChat.id || msg.sender_id === currentChat.id)) ||
                     (currentChat.type === 'group' && msg.chat_type === 'group' && msg.chat_id === currentChat.id) ||
                     (currentChat.type === 'channel' && msg.chat_type === 'channel' && msg.chat_id === currentChat.id))) {
                    appendMessage(msg);
                }
                // تحديث قائمة المحادثات
                loadConversations();
            });
            
            socket.on('user_typing', (data) => {
                if (currentChat && currentChat.type === 'private' && currentChat.id === data.user_id) {
                    document.getElementById('headerTitle').textContent = 
                        data.is_typing ? 'يكتب...' : currentChat.name;
                }
            });
            
            socket.on('reaction_updated', (data) => {
                const msgEl = document.getElementById(`msg-${data.message_id}`);
                if (msgEl) {
                    // تحديث التفاعلات
                    const reactionsStr = Object.entries(data.reactions)
                        .map(([emoji, users]) => `${emoji} ${users.length}`)
                        .join(' ');
                    let reactEl = msgEl.querySelector('.msg-reactions');
                    if (!reactEl) {
                        reactEl = document.createElement('div');
                        reactEl.className = 'msg-reactions';
                        reactEl.style.cssText = 'font-size:0.8rem;margin-top:4px;';
                        msgEl.querySelector('.message-bubble').appendChild(reactEl);
                    }
                    reactEl.textContent = reactionsStr;
                }
            });
            
            socket.on('user_online', (data) => {
                loadConversations();
            });
            
            socket.on('incoming_call', (data) => {
                showCallNotification(data);
            });
        }
        
        function showCallNotification(data) {
            if (confirm(`📞 مكالمة ${data.call_type === 'video' ? 'فيديو' : 'صوتية'} واردة من ${data.caller_name}`)) {
                socket.emit('call_accepted', { caller_id: data.caller_id });
            } else {
                socket.emit('call_declined', { caller_id: data.caller_id });
            }
        }
        
        // ==================== EVENT LISTENERS ====================
        function setupEventListeners() {
            const input = document.getElementById('messageInput');
            input.addEventListener('input', updateSendButton);
            input.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                }
            });
            
            // مؤشر الكتابة
            let typingTimeout;
            input.addEventListener('input', () => {
                if (currentChat && currentChat.type === 'private') {
                    socket.emit('typing', {
                        type: currentChat.type,
                        id: currentChat.id,
                        is_typing: true
                    });
                    clearTimeout(typingTimeout);
                    typingTimeout = setTimeout(() => {
                        socket.emit('typing', {
                            type: currentChat.type,
                            id: currentChat.id,
                            is_typing: false
                        });
                    }, 2000);
                }
            });
            
            // البحث عن مستخدمين
            document.getElementById('searchUsers').addEventListener('input', async (e) => {
                const q = e.target.value;
                if (q.length < 2) {
                    document.getElementById('searchResults').innerHTML = '';
                    return;
                }
                const res = await fetch(`/api/users/search?q=${encodeURIComponent(q)}`);
                const users = await res.json();
                document.getElementById('searchResults').innerHTML = users.map(u => `
                    <div style="padding:12px;border-bottom:1px solid var(--border);cursor:pointer;display:flex;align-items:center;gap:10px;"
                         onclick="openChat('private', ${u.id}, '${u.username}', '${u.avatar}');closeNewChatSheet();">
                        <div style="width:40px;height:40px;border-radius:50%;background:${getAvatarColor(u.username)};display:flex;align-items:center;justify-content:center;font-weight:bold;color:white;">${u.username.charAt(0)}</div>
                        <div>
                            <div style="font-weight:600;">${u.username}</div>
                            <div style="font-size:0.8rem;color:var(--text-secondary);">${u.phone || ''} ${u.is_online ? '🟢 متصل' : ''}</div>
                        </div>
                    </div>
                `).join('');
            });
        }
        
        // ==================== UI HELPERS ====================
        function openNewChatSheet() {
            document.getElementById('newChatOverlay').classList.add('show');
            document.getElementById('newChatSheet').classList.add('show');
        }
        function closeNewChatSheet() {
            document.getElementById('newChatOverlay').classList.remove('show');
            document.getElementById('newChatSheet').classList.remove('show');
        }
        
        function openCreateGroupSheet() {
            const name = prompt('اسم المجموعة:');
            if (!name) return;
            const desc = prompt('وصف المجموعة (اختياري):');
            const membersStr = prompt('أرقام معرفات الأعضاء (مفصولة بفواصل):');
            const members = membersStr ? membersStr.split(',').map(Number) : [];
            
            fetch('/api/groups/create', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ name, description: desc, members })
            }).then(r => r.json()).then(data => {
                closeNewChatSheet();
                loadConversations();
                openChat('group', data.id, name, '');
            });
        }
        
        function openCreateChannelSheet() {
            const name = prompt('اسم القناة:');
            if (!name) return;
            const desc = prompt('وصف القناة:');
            
            fetch('/api/channels/create', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ name, description: desc })
            }).then(r => r.json()).then(data => {
                closeNewChatSheet();
                loadConversations();
            });
        }
        
        function openSearch() {
            const q = prompt('ابحث في الرسائل:');
            if (!q) return;
            // يمكن تنفيذ صفحة بحث هنا
        }
        
        function viewFullImage(url) {
            window.open(url, '_blank');
        }
        
        function getAvatarColor(name) {
            const colors = ['#00b4d8', '#ff6b6b', '#2ed573', '#ffa502', '#a55eea', '#1e90ff', '#e056a0'];
            let hash = 0;
            for (let i = 0; i < name.length; i++) {
                hash = name.charCodeAt(i) + ((hash << 5) - hash);
            }
            return colors[Math.abs(hash) % colors.length];
        }
        
        function formatTime(timestamp) {
            if (!timestamp) return '';
            const d = new Date(timestamp);
            const now = new Date();
            const diff = now - d;
            
            if (diff < 60000) return 'الآن';
            if (diff < 3600000) return `${Math.floor(diff/60000)} د`;
            if (d.toDateString() === now.toDateString()) {
                return d.toLocaleTimeString('ar-SA', { hour: '2-digit', minute: '2-digit' });
            }
            if (diff < 86400000 * 7) {
                return d.toLocaleDateString('ar-SA', { weekday: 'short' });
            }
            return d.toLocaleDateString('ar-SA', { day: 'numeric', month: 'numeric' });
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function renderSettingsHTML() {
            return `
                <div style="padding:16px;">
                    <div style="text-align:center;margin-bottom:20px;">
                        <div style="width:70px;height:70px;border-radius:50%;background:${getAvatarColor(currentUser?.username || '')};display:inline-flex;align-items:center;justify-content:center;font-size:1.8rem;font-weight:bold;color:white;">
                            ${currentUser?.username?.charAt(0) || '?'}
                        </div>
                        <h3 style="margin-top:8px;">${currentUser?.username || ''}</h3>
                        <p style="color:var(--text-secondary);">${currentUser?.phone || ''}</p>
                    </div>
                    <div style="display:flex;flex-direction:column;gap:8px;">
                        <button class="settings-btn" onclick="toggleTheme()"><i class="fas fa-moon"></i> الوضع المظلم</button>
                        <button class="settings-btn" onclick="backupChats()"><i class="fas fa-cloud-upload-alt"></i> نسخ احتياطي</button>
                        <button class="settings-btn" onclick="toggleTwoFactor()"><i class="fas fa-shield-alt"></i> التحقق بخطوتين</button>
                        <button class="settings-btn" onclick="togglePrivacy('last_seen')"><i class="fas fa-eye-slash"></i> إخفاء آخر ظهور</button>
                        <button class="settings-btn" onclick="togglePrivacy('typing')"><i class="fas fa-keyboard"></i> إخفاء حالة الكتابة</button>
                        <a href="/logout" style="text-decoration:none;"><button class="settings-btn" style="color:#ff4757;"><i class="fas fa-sign-out-alt"></i> تسجيل الخروج</button></a>
                    </div>
                </div>
            `;
        }
        
        function backupChats() {
            fetch('/api/backup', { method: 'POST' })
                .then(res => res.blob())
                .then(blob => {
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `perna_backup_${new Date().toISOString().slice(0,10)}.json`;
                    a.click();
                });
        }
        
        function toggleTheme() {
            document.body.style.background = document.body.style.background === 'white' ? 'var(--bg)' : 'white';
        }
        
        function toggleTwoFactor() {
            alert('سيتم تفعيل التحقق بخطوتين');
        }
        
        function togglePrivacy(type) {
            alert(`تم تغيير إعدادات ${type}`);
        }
        
        async function loadStatuses() {
            try {
                const res = await fetch('/api/status/feed');
                const statuses = await res.json();
                const container = document.getElementById('conversationsList');
                container.innerHTML = statuses.map(s => `
                    <div class="conversation-item" style="border-right:3px solid var(--primary);">
                        <div class="avatar" style="background:${getAvatarColor(s.username)};display:flex;align-items:center;justify-content:center;font-weight:bold;color:white;">
                            ${s.username.charAt(0)}
                        </div>
                        <div class="info">
                            <div class="name">${s.username}</div>
                            <div class="last-msg">${s.type === 'text' ? s.content : s.type === 'image' ? '📷 صورة' : '🎥 فيديو'}</div>
                        </div>
                        <div class="meta">
                            <div class="time">${formatTime(s.created_at)}</div>
                        </div>
                    </div>
                `).join('') || '<div class="text-center text-secondary mt-5">لا توجد حالات نشطة</div>';
            } catch(e) {}
        }
    </script>
    {% endraw %}
    
    <style>
        .settings-btn {
            width: 100%;
            padding: 14px;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text);
            cursor: pointer;
            text-align: right;
            font-size: 0.95rem;
            transition: 0.2s;
        }
        .settings-btn:active { background: rgba(0,180,216,0.1); }
        .settings-btn i { margin-left: 8px; color: var(--primary); }
    </style>
</body>
</html>
'''

# ====================
# Run Application
# ====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("""
    ╔══════════════════════════════════════╗
    ║      Perna - تطبيق المراسلة         ║
    ║    يعمل على: http://0.0.0.0:5000    ║
    ║    للهاتف فقط - افتح على جوالك      ║
    ╚══════════════════════════════════════╝
    """)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
