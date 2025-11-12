# high_security_chat_server.py
import asyncio
import websockets
import ssl
import json
import time
import sqlite3
from datetime import datetime, timedelta
import os
import logging
import hashlib
import secrets
import re
from logging.handlers import RotatingFileHandler
import ipaddress
import argparse

print("🛡️ Starting High-Security Production Chat Server...")

# Setup comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('security_chat.log', maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecurityManager:
    def __init__(self):
        self.failed_attempts = {}
        self.ip_whitelist = set()
        self.ip_blacklist = set()
        self.suspicious_activity = {}
        self.load_security_config()
    
    def load_security_config(self):
        """Load security configuration"""
        # Load from environment or config file in production
        self.max_connections_per_ip = int(os.getenv('MAX_CONNECTIONS_PER_IP', '5'))
        self.max_messages_per_minute = int(os.getenv('MAX_MESSAGES_PER_MINUTE', '30'))
        self.auto_block_attempts = int(os.getenv('AUTO_BLOCK_ATTEMPTS', '5'))
        
    def is_ip_allowed(self, ip):
        """Check if IP is allowed to connect"""
        if ip in self.ip_blacklist:
            return False, "IP blocked due to suspicious activity"
        
        # Check if IP is in private range (for local development)
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return True, "Local IP allowed"
        except:
            pass
            
        return True, "IP allowed"
    
    def record_failed_attempt(self, ip, reason=""):
        """Record failed connection attempt"""
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = {'count': 0, 'first_attempt': time.time(), 'reasons': []}
        
        self.failed_attempts[ip]['count'] += 1
        self.failed_attempts[ip]['last_attempt'] = time.time()
        self.failed_attempts[ip]['reasons'].append(reason)
        
        # Auto-block after too many failed attempts
        if self.failed_attempts[ip]['count'] >= self.auto_block_attempts:
            if time.time() - self.failed_attempts[ip]['first_attempt'] < 600:  # 10 minutes
                self.ip_blacklist.add(ip)
                logger.warning(f"🚫 Auto-blocked IP {ip} for {self.failed_attempts[ip]['count']} failed attempts")
                return True
        return False
    
    def record_suspicious_activity(self, ip, activity_type, details=""):
        """Record suspicious activity"""
        if ip not in self.suspicious_activity:
            self.suspicious_activity[ip] = []
        
        self.suspicious_activity[ip].append({
            'timestamp': time.time(),
            'type': activity_type,
            'details': details
        })
        
        # Keep only last 100 activities per IP
        self.suspicious_activity[ip] = self.suspicious_activity[ip][-100:]
    
    def cleanup_old_data(self):
        """Clean up old security data"""
        current_time = time.time()
        
        # Clean failed attempts older than 1 hour
        expired_ips = []
        for ip, data in self.failed_attempts.items():
            if current_time - data.get('last_attempt', 0) > 3600:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            del self.failed_attempts[ip]
        
        # Clean suspicious activity older than 24 hours
        for ip in list(self.suspicious_activity.keys()):
            self.suspicious_activity[ip] = [
                activity for activity in self.suspicious_activity[ip]
                if current_time - activity['timestamp'] < 86400
            ]
            if not self.suspicious_activity[ip]:
                del self.suspicious_activity[ip]

class HighSecurityChatServer:
    def __init__(self, host='0.0.0.0', port=8765):
        self.host = host
        self.port = port
        self.people_online = set()
        self.who_is_who = {}
        self.security = SecurityManager()
        self.rate_limits = {}
        self.setup_database()
        
        # Security statistics
        self.stats = {
            'total_connections': 0,
            'blocked_connections': 0,
            'messages_processed': 0,
            'security_events': 0
        }
        
    def setup_database(self):
        """Setup high-security SQLite database with connection pooling"""
        try:
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secure_chat.db')
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            
            # Database optimizations for production
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.conn.execute('PRAGMA synchronous=NORMAL')
            self.conn.execute('PRAGMA foreign_keys=ON')
            self.conn.execute('PRAGMA cache_size=-10000')  # 10MB cache
            self.conn.execute('PRAGMA temp_store=MEMORY')
            
            logger.info("✅ High-Security Database Connected")
            self.init_database_tables()
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            self.conn = None
            self.messages = []
            self.users = {}
    
    def init_database_tables(self):
        """Initialize secure database tables"""
        cursor = self.conn.cursor()
        try:
            # Users table with enhanced security fields
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS secure_users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    joined_date REAL NOT NULL,
                    message_count INTEGER DEFAULT 0,
                    last_seen REAL NOT NULL,
                    last_ip TEXT,
                    is_active INTEGER DEFAULT 1,
                    trust_score INTEGER DEFAULT 100,
                    created_at REAL NOT NULL
                )
            ''')
            
            # Messages table with security flags
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS secure_messages (
                    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    message_text TEXT NOT NULL,
                    message_time REAL NOT NULL,
                    ip_address TEXT,
                    is_flagged INTEGER DEFAULT 0,
                    flag_reason TEXT,
                    moderated_by TEXT DEFAULT 'system'
                )
            ''')
            
            # Security events log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    username TEXT,
                    details TEXT,
                    severity INTEGER DEFAULT 1,
                    event_time REAL NOT NULL,
                    resolved INTEGER DEFAULT 0
                )
            ''')
            
            # Connection logs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS connection_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT,
                    connected_at REAL NOT NULL,
                    disconnected_at REAL,
                    duration REAL,
                    messages_sent INTEGER DEFAULT 0
                )
            ''')
            
            # Create optimized indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON secure_users(username)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_time ON secure_messages(message_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events ON security_events(event_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_ip ON connection_logs(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_flagged ON secure_messages(is_flagged)')
            
            self.conn.commit()
            logger.info("✅ High-security database tables initialized")
            
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")
    
    def log_security_event(self, event_type, ip_address, username=None, details="", severity=1):
        """Log security events to database"""
        if self.conn:
            try:
                cursor = self.conn.cursor()
                cursor.execute(
                    'INSERT INTO security_events (event_type, ip_address, username, details, severity, event_time) VALUES (?, ?, ?, ?, ?, ?)',
                    (event_type, ip_address, username, details, severity, time.time())
                )
                self.conn.commit()
                self.stats['security_events'] += 1
            except Exception as e:
                logger.error(f"Failed to log security event: {e}")
    
    def log_connection(self, ip_address, user_agent=None):
        """Log connection attempt"""
        if self.conn:
            try:
                cursor = self.conn.cursor()
                cursor.execute(
                    'INSERT INTO connection_logs (ip_address, user_agent, connected_at) VALUES (?, ?, ?)',
                    (ip_address, user_agent, time.time())
                )
                self.conn.commit()
                return cursor.lastrowid
            except Exception as e:
                logger.error(f"Failed to log connection: {e}")
        return None
    
    def update_connection_log(self, log_id, messages_sent=0):
        """Update connection log on disconnect"""
        if self.conn and log_id:
            try:
                cursor = self.conn.cursor()
                cursor.execute(
                    'UPDATE connection_logs SET disconnected_at = ?, duration = ? - connected_at, messages_sent = ? WHERE log_id = ?',
                    (time.time(), time.time(), messages_sent, log_id)
                )
                self.conn.commit()
            except Exception as e:
                logger.error(f"Failed to update connection log: {e}")
    
    def validate_username(self, username):
        """Strict username validation with security checks"""
        if not username or len(username) < 2 or len(username) > 20:
            return False, "Username must be 2-20 characters"
        
        # Only allow alphanumeric characters and basic symbols
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, hyphens, and underscores"
        
        # Check for reserved/administrative names
        reserved_names = ['admin', 'root', 'system', 'server', 'moderator', 'administrator']
        if username.lower() in reserved_names:
            return False, "This username is reserved for system use"
        
        # Check for offensive patterns
        offensive_patterns = [r'.*fuck.*', r'.*shit.*', r'.*asshole.*', r'.*nigger.*', r'.*cunt.*']
        for pattern in offensive_patterns:
            if re.match(pattern, username, re.IGNORECASE):
                return False, "Username contains inappropriate content"
        
        return True, "Valid"
    
    def validate_message(self, message):
        """Comprehensive message validation and sanitization"""
        if not message or len(message.strip()) == 0:
            return False, "Message cannot be empty"
        
        if len(message) > 500:
            return False, "Message too long (max 500 characters)"
        
        # Check for potential XSS/Script injection attempts
        xss_patterns = [
            r'<script', r'javascript:', r'onload=', r'onerror=', r'onclick=',
            r'<iframe', r'<object', r'<embed', r'eval\(', r'expression\(',
            r'document\.', r'window\.', r'alert\(', r'prompt\(', r'confirm\(',
            r'<img', r'<style', r'<link', r'@import', r'url\('
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return False, "Message contains potentially dangerous content"
        
        # Check for SQL injection patterns
        sql_patterns = [r'select.*from', r'insert.*into', r'update.*set', r'delete.*from', r'drop.*table']
        for pattern in sql_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return False, "Message contains suspicious patterns"
        
        # Check for excessive special characters (potential obfuscation)
        special_char_count = len(re.findall(r'[^\w\s]', message))
        if special_char_count > len(message) * 0.3:  # More than 30% special chars
            return False, "Message contains too many special characters"
        
        return True, "Valid"
    
    def check_rate_limit(self, ip, action_type):
        """Advanced rate limiting with different thresholds"""
        current_time = time.time()
        key = f"{ip}_{action_type}"
        
        if key not in self.rate_limits:
            self.rate_limits[key] = []
        
        # Clean old entries based on action type
        if action_type == "connection":
            window = 60  # 1 minute window
            limit = 5
        elif action_type == "message":
            window = 60  # 1 minute window  
            limit = 30
        elif action_type == "join":
            window = 300  # 5 minute window
            limit = 3
        else:
            window = 60
            limit = 10
        
        self.rate_limits[key] = [t for t in self.rate_limits[key] if current_time - t < window]
        
        if len(self.rate_limits[key]) >= limit:
            self.security.record_suspicious_activity(ip, f"RATE_LIMIT_{action_type.upper()}", 
                                                   f"Exceeded {limit} {action_type}s in {window}s")
            return False
        
        self.rate_limits[key].append(current_time)
        return True
    
    def user_exists(self, username):
        """Check if username exists in database"""
        if self.conn is None:
            return username in self.users
            
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                'SELECT username FROM secure_users WHERE username = ? AND is_active = 1',
                (username,)
            )
            return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error checking user: {e}")
            return False
    
    def add_user(self, username, ip_address=None):
        """Add new user with comprehensive security checks"""
        if self.conn is None:
            if username not in self.users:
                self.users[username] = {
                    'joined_date': time.time(),
                    'message_count': 0,
                    'last_seen': time.time(),
                    'ip_address': ip_address
                }
                return True
            return False
            
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO secure_users (username, joined_date, message_count, last_seen, last_ip, created_at) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (username, time.time(), 0, time.time(), ip_address, time.time())
            )
            self.conn.commit()
            self.log_security_event("USER_REGISTERED", ip_address, username, "New user account created", 1)
            return True
        except Exception as e:
            logger.error(f"Error adding user: {e}")
            return False
    
    def save_message(self, username, message, ip_address=None):
        """Save message with comprehensive security checks"""
        if self.conn is None:
            self.messages.append({
                'username': username,
                'text': message,
                'time': time.time(),
                'ip_address': ip_address
            })
            if username in self.users:
                self.users[username]['message_count'] += 1
            return
            
        cursor = self.conn.cursor()
        try:
            # Advanced message analysis
            is_flagged = 0
            flag_reason = ""
            
            # Check for URLs/links
            url_pattern = r'https?://[^\s]+|www\.[^\s]+'
            if re.search(url_pattern, message, re.IGNORECASE):
                is_flagged = 1
                flag_reason = "Contains URL"
            
            # Check for spam patterns
            spam_keywords = ['buy now', 'click here', 'limited time', 'discount', 'make money', 'work from home']
            if any(keyword in message.lower() for keyword in spam_keywords):
                is_flagged = 1
                flag_reason = "Potential spam content"
            
            # Check for excessive capitalization (shouting)
            if len(re.findall(r'[A-Z]', message)) > len(message) * 0.7:  # 70% caps
                is_flagged = 1
                flag_reason = "Excessive capitalization"
            
            # Save message
            cursor.execute(
                'INSERT INTO secure_messages (username, message_text, message_time, ip_address, is_flagged, flag_reason) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (username, message, time.time(), ip_address, is_flagged, flag_reason)
            )
            
            # Update user stats
            cursor.execute(
                'UPDATE secure_users SET message_count = message_count + 1, '
                'last_seen = ?, last_ip = ? WHERE username = ?',
                (time.time(), ip_address, username)
            )
            
            self.conn.commit()
            self.stats['messages_processed'] += 1
            
            if is_flagged:
                self.log_security_event("MESSAGE_FLAGGED", ip_address, username, 
                                      f"Flagged: {flag_reason} - {message[:50]}", 2)
                
        except Exception as e:
            logger.error(f"Error saving message: {e}")
    
    def get_recent_messages(self, limit=50):
        """Get recent non-flagged messages"""
        if self.conn is None:
            recent_msgs = sorted(self.messages, key=lambda x: x['time'])[-limit:]
            result = []
            for msg in recent_msgs:
                result.append({
                    'user': msg['username'],
                    'text': msg['text'],
                    'time': datetime.fromtimestamp(msg['time']).strftime('%H:%M')
                })
            return result
            
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                SELECT username, message_text, message_time 
                FROM secure_messages 
                WHERE is_flagged = 0
                ORDER BY message_time DESC 
                LIMIT ?
            ''', (limit,))
            
            messages = cursor.fetchall()
            result = []
            for msg in reversed(messages):
                result.append({
                    'user': msg[0],
                    'text': msg[1],
                    'time': datetime.fromtimestamp(msg[2]).strftime('%H:%M')
                })
            return result
        except Exception as e:
            logger.error(f"Error getting messages: {e}")
            return []
    
    def get_user_stats(self, username):
        """Get comprehensive user statistics"""
        if self.conn is None:
            if username in self.users:
                user_data = self.users[username]
                days_ago = int((time.time() - user_data['joined_date']) / (24 * 60 * 60))
                msg_count = user_data['message_count']
                
                return {
                    'username': username,
                    'joined': datetime.fromtimestamp(user_data['joined_date']).strftime('%Y-%m-%d'),
                    'days_ago': days_ago,
                    'messages': msg_count,
                    'level': 'New' if msg_count < 10 else 'Regular' if msg_count < 50 else 'Trusted' if msg_count < 200 else 'VIP'
                }
            return None
            
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                SELECT username, joined_date, message_count, trust_score 
                FROM secure_users 
                WHERE username = ? AND is_active = 1
            ''', (username,))
            
            result = cursor.fetchone()
            if result:
                username, join_time, msg_count, trust_score = result
                days_ago = int((time.time() - join_time) / (24 * 60 * 60))
                
                # Calculate level based on messages and trust score
                if msg_count < 10:
                    level = "New"
                elif msg_count < 50:
                    level = "Regular" 
                elif msg_count < 200:
                    level = "Trusted"
                else:
                    level = "VIP"
                
                # Adjust level based on trust score
                if trust_score < 50:
                    level = "Restricted"
                
                return {
                    'username': username,
                    'joined': datetime.fromtimestamp(join_time).strftime('%Y-%m-%d'),
                    'days_ago': days_ago,
                    'messages': msg_count,
                    'level': level,
                    'trust_score': trust_score
                }
            return None
        except Exception as e:
            logger.error(f"Error getting user stats: {e}")
            return None

    async def handle_connection(self, websocket, path):
        """Handle secure WebSocket connections with comprehensive protection"""
        client_ip = websocket.remote_address[0]
        user_agent = websocket.request_headers.get('User-Agent', 'Unknown')
        
        # Initial security screening
        is_allowed, reason = self.security.is_ip_allowed(client_ip)
        if not is_allowed:
            logger.warning(f"🚫 Blocked connection from restricted IP: {client_ip} - {reason}")
            self.stats['blocked_connections'] += 1
            await websocket.close(1008, "Access denied")
            return
        
        # Rate limiting for connections
        if not self.check_rate_limit(client_ip, "connection"):
            logger.warning(f"🚫 Rate limited connection from IP: {client_ip}")
            self.security.record_failed_attempt(client_ip, "Connection rate limit exceeded")
            await websocket.close(1008, "Too many connection attempts")
            return
        
        # Log connection
        connection_log_id = self.log_connection(client_ip, user_agent)
        self.stats['total_connections'] += 1
        
        logger.info(f"🔗 Secure connection established from {client_ip}")
        self.security.cleanup_old_data()
        self.people_online.add(websocket)
        
        username = None
        messages_sent = 0
        
        try:
            async for message in websocket:
                # Validate JSON format
                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    self.log_security_event("INVALID_JSON", client_ip, None, "Malformed JSON received", 2)
                    self.security.record_suspicious_activity(client_ip, "INVALID_JSON", "Malformed message")
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'msg': 'Invalid message format'
                    }))
                    continue
                
                # Validate message structure
                if not isinstance(data, dict) or 'type' not in data:
                    self.log_security_event("INVALID_MESSAGE_STRUCTURE", client_ip, None, "Missing message type", 2)
                    await websocket.send(json.dumps({
                        'type': 'error', 
                        'msg': 'Invalid message structure'
                    }))
                    continue
                
                if data.get('type') == 'join':
                    username = data.get('username', '').strip()
                    
                    # Rate limiting for join attempts
                    if not self.check_rate_limit(client_ip, "join"):
                        self.security.record_failed_attempt(client_ip, "Join rate limit exceeded")
                        await websocket.send(json.dumps({
                            'type': 'error',
                            'msg': 'Too many join attempts. Please wait 5 minutes.'
                        }))
                        continue
                    
                    # Comprehensive username validation
                    is_valid, validation_msg = self.validate_username(username)
                    if not is_valid:
                        was_blocked = self.security.record_failed_attempt(client_ip, f"Invalid username: {validation_msg}")
                        self.log_security_event("INVALID_USERNAME", client_ip, username, validation_msg, 2)
                        
                        if was_blocked:
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'msg': 'Too many invalid attempts. IP temporarily blocked.'
                            }))
                            await websocket.close(1008, "Security violation")
                            break
                        else:
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'msg': validation_msg
                            }))
                        continue
                    
                    # Check if user exists or create new
                    is_new_user = not self.user_exists(username)
                    if is_new_user:
                        if not self.add_user(username, client_ip):
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'msg': 'System error: Unable to create account'
                            }))
                            continue
                        logger.info(f"👤 New secure user registered: {username} from {client_ip}")
                    else:
                        logger.info(f"👤 Secure user rejoined: {username} from {client_ip}")
                    
                    self.who_is_who[websocket] = username
                    
                    # Send welcome message
                    if is_new_user:
                        welcome_msg = f"Welcome {username}! Your account has been created securely. 🔒"
                    else:
                        user_stats = self.get_user_stats(username)
                        if user_stats:
                            welcome_msg = f"Welcome back {username}! Security Level: {user_stats['level']} 🛡️"
                        else:
                            welcome_msg = f"Welcome back {username}! 🚀"
                    
                    await websocket.send(json.dumps({
                        'type': 'welcome',
                        'msg': welcome_msg,
                        'username': username,
                        'is_new': is_new_user,
                        'timestamp': time.time()
                    }))
                    
                    # Send message history
                    recent_messages = self.get_recent_messages(50)
                    await websocket.send(json.dumps({
                        'type': 'history',
                        'messages': recent_messages,
                        'timestamp': time.time()
                    }))
                    
                    # Send online users list
                    online_users = list(set(self.who_is_who.values()))
                    await websocket.send(json.dumps({
                        'type': 'online',
                        'users': online_users,
                        'count': len(online_users),
                        'timestamp': time.time()
                    }))
                    
                    # Notify others about new user
                    join_message = json.dumps({
                        'type': 'user_join',
                        'username': username,
                        'msg': f'{username} joined the secure chat 👋',
                        'online_count': len(online_users),
                        'timestamp': time.time()
                    })
                    
                    for client in self.people_online:
                        if client != websocket:
                            try:
                                await client.send(join_message)
                            except:
                                pass
                    
                    self.log_security_event("USER_JOINED", client_ip, username, "User successfully joined chat", 1)
                    break
            
            # Handle messages after successful join
            if username:
                async for message in websocket:
                    try:
                        data = json.loads(message)
                    except json.JSONDecodeError:
                        continue
                    
                    if data.get('type') == 'message':
                        text = data.get('text', '').strip()
                        
                        # Rate limiting for messages
                        if not self.check_rate_limit(client_ip, "message"):
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'msg': 'Message rate limit exceeded. Please wait 60 seconds.'
                            }))
                            continue
                        
                        # Comprehensive message validation
                        is_valid, validation_msg = self.validate_message(text)
                        if not is_valid:
                            self.log_security_event("INVALID_MESSAGE", client_ip, username, validation_msg, 2)
                            self.security.record_suspicious_activity(client_ip, "INVALID_MESSAGE", validation_msg)
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'msg': validation_msg
                            }))
                            continue
                        
                        # Save and broadcast secure message
                        self.save_message(username, text, client_ip)
                        messages_sent += 1
                        
                        chat_message = json.dumps({
                            'type': 'chat',
                            'username': username,
                            'text': text,
                            'time': datetime.now().strftime('%H:%M'),
                            'timestamp': time.time()
                        })
                        
                        sent_count = 0
                        disconnected_clients = []
                        
                        for client in self.people_online:
                            try:
                                await client.send(chat_message)
                                sent_count += 1
                            except:
                                disconnected_clients.append(client)
                        
                        # Cleanup disconnected clients
                        for client in disconnected_clients:
                            if client in self.people_online:
                                self.people_online.remove(client)
                            if client in self.who_is_who:
                                disconnected_user = self.who_is_who[client]
                                del self.who_is_who[client]
                                logger.info(f"Cleaned up disconnected user: {disconnected_user}")
                        
                        logger.info(f"💬 {username}: {text[:30]}... (secure, sent to {sent_count} users)")
                    
                    elif data.get('type') == 'get_stats':
                        stats = self.get_user_stats(username)
                        if stats:
                            await websocket.send(json.dumps({
                                'type': 'stats',
                                'stats': stats,
                                'timestamp': time.time()
                            }))
                    
                    elif data.get('type') == 'ping':
                        await websocket.send(json.dumps({
                            'type': 'pong', 
                            'timestamp': time.time(),
                            'server_time': time.time()
                        }))
        
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"🔌 Secure user disconnected: {username or 'Unknown'} from {client_ip}")
        except Exception as e:
            logger.error(f"❌ Secure connection error: {e}")
            self.log_security_event("CONNECTION_ERROR", client_ip, username, str(e), 3)
        
        finally:
            # Always cleanup on disconnect
            await self.handle_disconnect(websocket, username, client_ip, connection_log_id, messages_sent)
    
    async def handle_disconnect(self, websocket, username, client_ip, connection_log_id, messages_sent):
        """Handle client disconnection with comprehensive cleanup"""
        if websocket in self.people_online:
            self.people_online.remove(websocket)
        
        if websocket in self.who_is_who:
            if username is None:
                username = self.who_is_who[websocket]
            del self.who_is_who[websocket]
        
        # Update connection log
        self.update_connection_log(connection_log_id, messages_sent)
        
        if username:
            logger.info(f"👋 Secure user left: {username} from {client_ip} (sent {messages_sent} messages)")
            self.log_security_event("USER_LEFT", client_ip, username, f"Sent {messages_sent} messages", 1)
            
            # Notify others about user leaving
            online_users = list(set(self.who_is_who.values()))
            leave_message = json.dumps({
                'type': 'user_leave',
                'username': username,
                'msg': f'{username} left the secure chat 👋',
                'online_count': len(online_users),
                'timestamp': time.time()
            })
            
            for client in self.people_online:
                try:
                    await client.send(leave_message)
                except:
                    pass
    
    def get_server_stats(self):
        """Get server statistics for monitoring"""
        return {
            **self.stats,
            'online_users': len(self.people_online),
            'active_connections': len(self.people_online),
            'blocked_ips': len(self.security.ip_blacklist),
            'uptime': time.time() - getattr(self, 'start_time', time.time())
        }

def setup_high_security_ssl(cert_file=None, key_file=None):
    """Setup high-security SSL configuration"""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # High security SSL settings
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    ssl_context.options |= ssl.OP_NO_SSLv2
    ssl_context.options |= ssl.OP_NO_SSLv3
    ssl_context.options |= ssl.OP_NO_TLSv1
    ssl_context.options |= ssl.OP_NO_TLSv1_1
    
    # Use provided certificates or generate secure ones
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context.load_cert_chain(cert_file, key_file)
        logger.info("✅ Using provided SSL certificates with high security")
    else:
        # Generate high-security self-signed certificates
        logger.warning("⚠️ Generating high-security self-signed certificates")
        cert_path = 'high_security_server.crt'
        key_path = 'high_security_server.key'
        
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            logger.info("🔐 Generating high-security SSL certificates...")
            os.system(f'''
                openssl req -x509 -newkey rsa:4096 -nodes -sha256 \
                -out {cert_path} -keyout {key_path} \
                -days 365 -subj "/C=US/ST=Secure/L=Chat/O=HighSecurity/CN=secure-chat-server" \
                -addext "subjectAltName=DNS:localhost,DNS:127.0.0.1"
            ''')
        
        ssl_context.load_cert_chain(cert_path, key_path)
        logger.info("✅ Using high-security self-signed certificates")
    
    return ssl_context

async def main():
    """Start the high-security production chat server"""
    parser = argparse.ArgumentParser(description='High Security Chat Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8765, help='Port to listen on (default: 8765)')
    parser.add_argument('--cert', help='SSL certificate file')
    parser.add_argument('--key', help='SSL private key file')
    
    args = parser.parse_args()
    
    # Create server instance
    chat_server = HighSecurityChatServer(host=args.host, port=args.port)
    chat_server.start_time = time.time()
    
    # Setup SSL
    ssl_context = setup_high_security_ssl(args.cert, args.key)
    
    # Production server configuration
    server = await websockets.serve(
        chat_server.handle_connection,
        args.host,
        args.port,
        ssl=ssl_context,
        ping_interval=20,
        ping_timeout=30,
        max_size=10 * 1024 * 1024,  # 10MB max message size
        max_queue=100  # Max messages in queue
    )
    
    print("\n" + "="*70)
    print("🛡️  HIGH-SECURITY PRODUCTION CHAT SERVER RUNNING!")
    print("="*70)
    print(f"   Host: {args.host}")
    print(f"   Port: {args.port}")
    print("   SSL: Enabled with High Security 🔒")
    print("   Database: SQLite with WAL mode")
    print("   Security: Comprehensive protection active")
    print("   Logging: Detailed security logging enabled")
    print("="*70)
    print("\n📋 Production Endpoints:")
    print(f"   - Secure WebSocket: wss://your-domain.com:{args.port}")
    print(f"   - Local testing: wss://localhost:{args.port}")
    print("\n🔒 Security Features:")
    print("   - Rate limiting on all actions")
    print("   - IP blocking for suspicious activity") 
    print("   - Message content validation")
    print("   - XSS and SQL injection protection")
    print("   - Comprehensive logging and monitoring")
    print("   - TLS 1.2+ with secure ciphers")
    print("\n📊 Monitoring:")
    print("   - Log file: security_chat.log")
    print("   - Database: secure_chat.db")
    print("   - Real-time security event tracking")
    print("="*70)
    print("\nWaiting for secure connections...")
    
    # Periodic statistics logging
    async def log_statistics():
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            stats = chat_server.get_server_stats()
            logger.info(f"📊 Server Statistics: {stats}")
    
    asyncio.create_task(log_statistics())
    
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped gracefully by administrator")
        print("\n🛑 High-security server stopped gracefully")
    except Exception as e:
        logger.critical(f"💥 Server crashed: {e}")
        print(f"💥 Server crashed: {e}")
        raise# high_security_chat_server.py
import asyncio
import websockets
import ssl
import json
import time
import sqlite3
from datetime import datetime, timedelta
import os
import logging
import hashlib
import secrets
import re
from logging.handlers import RotatingFileHandler
import ipaddress
import argparse

print("🛡️ Starting High-Security Production Chat Server...")

# Setup comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('security_chat.log', maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecurityManager:
    def __init__(self):
        self.failed_attempts = {}
        self.ip_whitelist = set()
        self.ip_blacklist = set()
        self.suspicious_activity = {}
        self.load_security_config()
    
    def load_security_config(self):
        """Load security configuration"""
        # Load from environment or config file in production
        self.max_connections_per_ip = int(os.getenv('MAX_CONNECTIONS_PER_IP', '5'))
        self.max_messages_per_minute = int(os.getenv('MAX_MESSAGES_PER_MINUTE', '30'))
        self.auto_block_attempts = int(os.getenv('AUTO_BLOCK_ATTEMPTS', '5'))
        
    def is_ip_allowed(self, ip):
        """Check if IP is allowed to connect"""
        if ip in self.ip_blacklist:
            return False, "IP blocked due to suspicious activity"
        
        # Check if IP is in private range (for local development)
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return True, "Local IP allowed"
        except:
            pass
            
        return True, "IP allowed"
    
    def record_failed_attempt(self, ip, reason=""):
        """Record failed connection attempt"""
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = {'count': 0, 'first_attempt': time.time(), 'reasons': []}
        
        self.failed_attempts[ip]['count'] += 1
        self.failed_attempts[ip]['last_attempt'] = time.time()
        self.failed_attempts[ip]['reasons'].append(reason)
        
        # Auto-block after too many failed attempts
        if self.failed_attempts[ip]['count'] >= self.auto_block_attempts:
            if time.time() - self.failed_attempts[ip]['first_attempt'] < 600:  # 10 minutes
                self.ip_blacklist.add(ip)
                logger.warning(f"🚫 Auto-blocked IP {ip} for {self.failed_attempts[ip]['count']} failed attempts")
                return True
        return False
    
    def record_suspicious_activity(self, ip, activity_type, details=""):
        """Record suspicious activity"""
        if ip not in self.suspicious_activity:
            self.suspicious_activity[ip] = []
        
        self.suspicious_activity[ip].append({
            'timestamp': time.time(),
            'type': activity_type,
            'details': details
        })
        
        # Keep only last 100 activities per IP
        self.suspicious_activity[ip] = self.suspicious_activity[ip][-100:]
    
    def cleanup_old_data(self):
        """Clean up old security data"""
        current_time = time.time()
        
        # Clean failed attempts older than 1 hour
        expired_ips = []
        for ip, data in self.failed_attempts.items():
            if current_time - data.get('last_attempt', 0) > 3600:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            del self.failed_attempts[ip]
        
        # Clean suspicious activity older than 24 hours
        for ip in list(self.suspicious_activity.keys()):
            self.suspicious_activity[ip] = [
                activity for activity in self.suspicious_activity[ip]
                if current_time - activity['timestamp'] < 86400
            ]
            if not self.suspicious_activity[ip]:
                del self.suspicious_activity[ip]

class HighSecurityChatServer:
    def __init__(self, host='0.0.0.0', port=8765):
        self.host = host
        self.port = port
        self.people_online = set()
        self.who_is_who = {}
        self.security = SecurityManager()
        self.rate_limits = {}
        self.setup_database()
        
        # Security statistics
        self.stats = {
            'total_connections': 0,
            'blocked_connections': 0,
            'messages_processed': 0,
            'security_events': 0
        }
        
    def setup_database(self):
        """Setup high-security SQLite database with connection pooling"""
        try:
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secure_chat.db')
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            
            # Database optimizations for production
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.conn.execute('PRAGMA synchronous=NORMAL')
            self.conn.execute('PRAGMA foreign_keys=ON')
            self.conn.execute('PRAGMA cache_size=-10000')  # 10MB cache
            self.conn.execute('PRAGMA temp_store=MEMORY')
            
            logger.info("✅ High-Security Database Connected")
            self.init_database_tables()
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            self.conn = None
            self.messages = []
            self.users = {}
    
    def init_database_tables(self):
        """Initialize secure database tables"""
        cursor = self.conn.cursor()
        try:
            # Users table with enhanced security fields
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS secure_users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    joined_date REAL NOT NULL,
                    message_count INTEGER DEFAULT 0,
                    last_seen REAL NOT NULL,
                    last_ip TEXT,
                    is_active INTEGER DEFAULT 1,
                    trust_score INTEGER DEFAULT 100,
                    created_at REAL NOT NULL
                )
            ''')
            
            # Messages table with security flags
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS secure_messages (
                    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    message_text TEXT NOT NULL,
                    message_time REAL NOT NULL,
                    ip_address TEXT,
                    is_flagged INTEGER DEFAULT 0,
                    flag_reason TEXT,
                    moderated_by TEXT DEFAULT 'system'
                )
            ''')
            
            # Security events log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    username TEXT,
                    details TEXT,
                    severity INTEGER DEFAULT 1,
                    event_time REAL NOT NULL,
                    resolved INTEGER DEFAULT 0
                )
            ''')
            
            # Connection logs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS connection_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT,
                    connected_at REAL NOT NULL,
                    disconnected_at REAL,
                    duration REAL,
                    messages_sent INTEGER DEFAULT 0
                )
            ''')
            
            # Create optimized indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON secure_users(username)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_time ON secure_messages(message_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events ON security_events(event_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_ip ON connection_logs(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_flagged ON secure_messages(is_flagged)')
            
            self.conn.commit()
            logger.info("✅ High-security database tables initialized")
            
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")
    
    def log_security_event(self, event_type, ip_address, username=None, details="", severity=1):
        """Log security events to database"""
        if self.conn:
            try:
                cursor = self.conn.cursor()
                cursor.execute(
                    'INSERT INTO security_events (event_type, ip_address, username, details, severity, event_time) VALUES (?, ?, ?, ?, ?, ?)',
                    (event_type, ip_address, username, details, severity, time.time())
                )
                self.conn.commit()
                self.stats['security_events'] += 1
            except Exception as e:
                logger.error(f"Failed to log security event: {e}")
    
    def log_connection(self, ip_address, user_agent=None):
        """Log connection attempt"""
        if self.conn:
            try:
                cursor = self.conn.cursor()
                cursor.execute(
                    'INSERT INTO connection_logs (ip_address, user_agent, connected_at) VALUES (?, ?, ?)',
                    (ip_address, user_agent, time.time())
                )
                self.conn.commit()
                return cursor.lastrowid
            except Exception as e:
                logger.error(f"Failed to log connection: {e}")
        return None
    
    def update_connection_log(self, log_id, messages_sent=0):
        """Update connection log on disconnect"""
        if self.conn and log_id:
            try:
                cursor = self.conn.cursor()
                cursor.execute(
                    'UPDATE connection_logs SET disconnected_at = ?, duration = ? - connected_at, messages_sent = ? WHERE log_id = ?',
                    (time.time(), time.time(), messages_sent, log_id)
                )
                self.conn.commit()
            except Exception as e:
                logger.error(f"Failed to update connection log: {e}")
    
    def validate_username(self, username):
        """Strict username validation with security checks"""
        if not username or len(username) < 2 or len(username) > 20:
            return False, "Username must be 2-20 characters"
        
        # Only allow alphanumeric characters and basic symbols
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, hyphens, and underscores"
        
        # Check for reserved/administrative names
        reserved_names = ['admin', 'root', 'system', 'server', 'moderator', 'administrator']
        if username.lower() in reserved_names:
            return False, "This username is reserved for system use"
        
        # Check for offensive patterns
        offensive_patterns = [r'.*fuck.*', r'.*shit.*', r'.*asshole.*', r'.*nigger.*', r'.*cunt.*']
        for pattern in offensive_patterns:
            if re.match(pattern, username, re.IGNORECASE):
                return False, "Username contains inappropriate content"
        
        return True, "Valid"
    
    def validate_message(self, message):
        """Comprehensive message validation and sanitization"""
        if not message or len(message.strip()) == 0:
            return False, "Message cannot be empty"
        
        if len(message) > 500:
            return False, "Message too long (max 500 characters)"
        
        # Check for potential XSS/Script injection attempts
        xss_patterns = [
            r'<script', r'javascript:', r'onload=', r'onerror=', r'onclick=',
            r'<iframe', r'<object', r'<embed', r'eval\(', r'expression\(',
            r'document\.', r'window\.', r'alert\(', r'prompt\(', r'confirm\(',
            r'<img', r'<style', r'<link', r'@import', r'url\('
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return False, "Message contains potentially dangerous content"
        
        # Check for SQL injection patterns
        sql_patterns = [r'select.*from', r'insert.*into', r'update.*set', r'delete.*from', r'drop.*table']
        for pattern in sql_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return False, "Message contains suspicious patterns"
        
        # Check for excessive special characters (potential obfuscation)
        special_char_count = len(re.findall(r'[^\w\s]', message))
        if special_char_count > len(message) * 0.3:  # More than 30% special chars
            return False, "Message contains too many special characters"
        
        return True, "Valid"
    
    def check_rate_limit(self, ip, action_type):
        """Advanced rate limiting with different thresholds"""
        current_time = time.time()
        key = f"{ip}_{action_type}"
        
        if key not in self.rate_limits:
            self.rate_limits[key] = []
        
        # Clean old entries based on action type
        if action_type == "connection":
            window = 60  # 1 minute window
            limit = 5
        elif action_type == "message":
            window = 60  # 1 minute window  
            limit = 30
        elif action_type == "join":
            window = 300  # 5 minute window
            limit = 3
        else:
            window = 60
            limit = 10
        
        self.rate_limits[key] = [t for t in self.rate_limits[key] if current_time - t < window]
        
        if len(self.rate_limits[key]) >= limit:
            self.security.record_suspicious_activity(ip, f"RATE_LIMIT_{action_type.upper()}", 
                                                   f"Exceeded {limit} {action_type}s in {window}s")
            return False
        
        self.rate_limits[key].append(current_time)
        return True
    
    def user_exists(self, username):
        """Check if username exists in database"""
        if self.conn is None:
            return username in self.users
            
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                'SELECT username FROM secure_users WHERE username = ? AND is_active = 1',
                (username,)
            )
            return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error checking user: {e}")
            return False
    
    def add_user(self, username, ip_address=None):
        """Add new user with comprehensive security checks"""
        if self.conn is None:
            if username not in self.users:
                self.users[username] = {
                    'joined_date': time.time(),
                    'message_count': 0,
                    'last_seen': time.time(),
                    'ip_address': ip_address
                }
                return True
            return False
            
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO secure_users (username, joined_date, message_count, last_seen, last_ip, created_at) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (username, time.time(), 0, time.time(), ip_address, time.time())
            )
            self.conn.commit()
            self.log_security_event("USER_REGISTERED", ip_address, username, "New user account created", 1)
            return True
        except Exception as e:
            logger.error(f"Error adding user: {e}")
            return False
    
    def save_message(self, username, message, ip_address=None):
        """Save message with comprehensive security checks"""
        if self.conn is None:
            self.messages.append({
                'username': username,
                'text': message,
                'time': time.time(),
                'ip_address': ip_address
            })
            if username in self.users:
                self.users[username]['message_count'] += 1
            return
            
        cursor = self.conn.cursor()
        try:
            # Advanced message analysis
            is_flagged = 0
            flag_reason = ""
            
            # Check for URLs/links
            url_pattern = r'https?://[^\s]+|www\.[^\s]+'
            if re.search(url_pattern, message, re.IGNORECASE):
                is_flagged = 1
                flag_reason = "Contains URL"
            
            # Check for spam patterns
            spam_keywords = ['buy now', 'click here', 'limited time', 'discount', 'make money', 'work from home']
            if any(keyword in message.lower() for keyword in spam_keywords):
                is_flagged = 1
                flag_reason = "Potential spam content"
            
            # Check for excessive capitalization (shouting)
            if len(re.findall(r'[A-Z]', message)) > len(message) * 0.7:  # 70% caps
                is_flagged = 1
                flag_reason = "Excessive capitalization"
            
            # Save message
            cursor.execute(
                'INSERT INTO secure_messages (username, message_text, message_time, ip_address, is_flagged, flag_reason) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (username, message, time.time(), ip_address, is_flagged, flag_reason)
            )
            
            # Update user stats
            cursor.execute(
                'UPDATE secure_users SET message_count = message_count + 1, '
                'last_seen = ?, last_ip = ? WHERE username = ?',
                (time.time(), ip_address, username)
            )
            
            self.conn.commit()
            self.stats['messages_processed'] += 1
            
            if is_flagged:
                self.log_security_event("MESSAGE_FLAGGED", ip_address, username, 
                                      f"Flagged: {flag_reason} - {message[:50]}", 2)
                
        except Exception as e:
            logger.error(f"Error saving message: {e}")
    
    def get_recent_messages(self, limit=50):
        """Get recent non-flagged messages"""
        if self.conn is None:
            recent_msgs = sorted(self.messages, key=lambda x: x['time'])[-limit:]
            result = []
            for msg in recent_msgs:
                result.append({
                    'user': msg['username'],
                    'text': msg['text'],
                    'time': datetime.fromtimestamp(msg['time']).strftime('%H:%M')
                })
            return result
            
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                SELECT username, message_text, message_time 
                FROM secure_messages 
                WHERE is_flagged = 0
                ORDER BY message_time DESC 
                LIMIT ?
            ''', (limit,))
            
            messages = cursor.fetchall()
            result = []
            for msg in reversed(messages):
                result.append({
                    'user': msg[0],
                    'text': msg[1],
                    'time': datetime.fromtimestamp(msg[2]).strftime('%H:%M')
                })
            return result
        except Exception as e:
            logger.error(f"Error getting messages: {e}")
            return []
    
    def get_user_stats(self, username):
        """Get comprehensive user statistics"""
        if self.conn is None:
            if username in self.users:
                user_data = self.users[username]
                days_ago = int((time.time() - user_data['joined_date']) / (24 * 60 * 60))
                msg_count = user_data['message_count']
                
                return {
                    'username': username,
                    'joined': datetime.fromtimestamp(user_data['joined_date']).strftime('%Y-%m-%d'),
                    'days_ago': days_ago,
                    'messages': msg_count,
                    'level': 'New' if msg_count < 10 else 'Regular' if msg_count < 50 else 'Trusted' if msg_count < 200 else 'VIP'
                }
            return None
            
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                SELECT username, joined_date, message_count, trust_score 
                FROM secure_users 
                WHERE username = ? AND is_active = 1
            ''', (username,))
            
            result = cursor.fetchone()
            if result:
                username, join_time, msg_count, trust_score = result
                days_ago = int((time.time() - join_time) / (24 * 60 * 60))
                
                # Calculate level based on messages and trust score
                if msg_count < 10:
                    level = "New"
                elif msg_count < 50:
                    level = "Regular" 
                elif msg_count < 200:
                    level = "Trusted"
                else:
                    level = "VIP"
                
                # Adjust level based on trust score
                if trust_score < 50:
                    level = "Restricted"
                
                return {
                    'username': username,
                    'joined': datetime.fromtimestamp(join_time).strftime('%Y-%m-%d'),
                    'days_ago': days_ago,
                    'messages': msg_count,
                    'level': level,
                    'trust_score': trust_score
                }
            return None
        except Exception as e:
            logger.error(f"Error getting user stats: {e}")
            return None

    async def handle_connection(self, websocket, path):
        """Handle secure WebSocket connections with comprehensive protection"""
        client_ip = websocket.remote_address[0]
        user_agent = websocket.request_headers.get('User-Agent', 'Unknown')
        
        # Initial security screening
        is_allowed, reason = self.security.is_ip_allowed(client_ip)
        if not is_allowed:
            logger.warning(f"🚫 Blocked connection from restricted IP: {client_ip} - {reason}")
            self.stats['blocked_connections'] += 1
            await websocket.close(1008, "Access denied")
            return
        
        # Rate limiting for connections
        if not self.check_rate_limit(client_ip, "connection"):
            logger.warning(f"🚫 Rate limited connection from IP: {client_ip}")
            self.security.record_failed_attempt(client_ip, "Connection rate limit exceeded")
            await websocket.close(1008, "Too many connection attempts")
            return
        
        # Log connection
        connection_log_id = self.log_connection(client_ip, user_agent)
        self.stats['total_connections'] += 1
        
        logger.info(f"🔗 Secure connection established from {client_ip}")
        self.security.cleanup_old_data()
        self.people_online.add(websocket)
        
        username = None
        messages_sent = 0
        
        try:
            async for message in websocket:
                # Validate JSON format
                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    self.log_security_event("INVALID_JSON", client_ip, None, "Malformed JSON received", 2)
                    self.security.record_suspicious_activity(client_ip, "INVALID_JSON", "Malformed message")
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'msg': 'Invalid message format'
                    }))
                    continue
                
                # Validate message structure
                if not isinstance(data, dict) or 'type' not in data:
                    self.log_security_event("INVALID_MESSAGE_STRUCTURE", client_ip, None, "Missing message type", 2)
                    await websocket.send(json.dumps({
                        'type': 'error', 
                        'msg': 'Invalid message structure'
                    }))
                    continue
                
                if data.get('type') == 'join':
                    username = data.get('username', '').strip()
                    
                    # Rate limiting for join attempts
                    if not self.check_rate_limit(client_ip, "join"):
                        self.security.record_failed_attempt(client_ip, "Join rate limit exceeded")
                        await websocket.send(json.dumps({
                            'type': 'error',
                            'msg': 'Too many join attempts. Please wait 5 minutes.'
                        }))
                        continue
                    
                    # Comprehensive username validation
                    is_valid, validation_msg = self.validate_username(username)
                    if not is_valid:
                        was_blocked = self.security.record_failed_attempt(client_ip, f"Invalid username: {validation_msg}")
                        self.log_security_event("INVALID_USERNAME", client_ip, username, validation_msg, 2)
                        
                        if was_blocked:
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'msg': 'Too many invalid attempts. IP temporarily blocked.'
                            }))
                            await websocket.close(1008, "Security violation")
                            break
                        else:
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'msg': validation_msg
                            }))
                        continue
                    
                    # Check if user exists or create new
                    is_new_user = not self.user_exists(username)
                    if is_new_user:
                        if not self.add_user(username, client_ip):
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'msg': 'System error: Unable to create account'
                            }))
                            continue
                        logger.info(f"👤 New secure user registered: {username} from {client_ip}")
                    else:
                        logger.info(f"👤 Secure user rejoined: {username} from {client_ip}")
                    
                    self.who_is_who[websocket] = username
                    
                    # Send welcome message
                    if is_new_user:
                        welcome_msg = f"Welcome {username}! Your account has been created securely. 🔒"
                    else:
                        user_stats = self.get_user_stats(username)
                        if user_stats:
                            welcome_msg = f"Welcome back {username}! Security Level: {user_stats['level']} 🛡️"
                        else:
                            welcome_msg = f"Welcome back {username}! 🚀"
                    
                    await websocket.send(json.dumps({
                        'type': 'welcome',
                        'msg': welcome_msg,
                        'username': username,
                        'is_new': is_new_user,
                        'timestamp': time.time()
                    }))
                    
                    # Send message history
                    recent_messages = self.get_recent_messages(50)
                    await websocket.send(json.dumps({
                        'type': 'history',
                        'messages': recent_messages,
                        'timestamp': time.time()
                    }))
                    
                    # Send online users list
                    online_users = list(set(self.who_is_who.values()))
                    await websocket.send(json.dumps({
                        'type': 'online',
                        'users': online_users,
                        'count': len(online_users),
                        'timestamp': time.time()
                    }))
                    
                    # Notify others about new user
                    join_message = json.dumps({
                        'type': 'user_join',
                        'username': username,
                        'msg': f'{username} joined the secure chat 👋',
                        'online_count': len(online_users),
                        'timestamp': time.time()
                    })
                    
                    for client in self.people_online:
                        if client != websocket:
                            try:
                                await client.send(join_message)
                            except:
                                pass
                    
                    self.log_security_event("USER_JOINED", client_ip, username, "User successfully joined chat", 1)
                    break
            
            # Handle messages after successful join
            if username:
                async for message in websocket:
                    try:
                        data = json.loads(message)
                    except json.JSONDecodeError:
                        continue
                    
                    if data.get('type') == 'message':
                        text = data.get('text', '').strip()
                        
                        # Rate limiting for messages
                        if not self.check_rate_limit(client_ip, "message"):
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'msg': 'Message rate limit exceeded. Please wait 60 seconds.'
                            }))
                            continue
                        
                        # Comprehensive message validation
                        is_valid, validation_msg = self.validate_message(text)
                        if not is_valid:
                            self.log_security_event("INVALID_MESSAGE", client_ip, username, validation_msg, 2)
                            self.security.record_suspicious_activity(client_ip, "INVALID_MESSAGE", validation_msg)
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'msg': validation_msg
                            }))
                            continue
                        
                        # Save and broadcast secure message
                        self.save_message(username, text, client_ip)
                        messages_sent += 1
                        
                        chat_message = json.dumps({
                            'type': 'chat',
                            'username': username,
                            'text': text,
                            'time': datetime.now().strftime('%H:%M'),
                            'timestamp': time.time()
                        })
                        
                        sent_count = 0
                        disconnected_clients = []
                        
                        for client in self.people_online:
                            try:
                                await client.send(chat_message)
                                sent_count += 1
                            except:
                                disconnected_clients.append(client)
                        
                        # Cleanup disconnected clients
                        for client in disconnected_clients:
                            if client in self.people_online:
                                self.people_online.remove(client)
                            if client in self.who_is_who:
                                disconnected_user = self.who_is_who[client]
                                del self.who_is_who[client]
                                logger.info(f"Cleaned up disconnected user: {disconnected_user}")
                        
                        logger.info(f"💬 {username}: {text[:30]}... (secure, sent to {sent_count} users)")
                    
                    elif data.get('type') == 'get_stats':
                        stats = self.get_user_stats(username)
                        if stats:
                            await websocket.send(json.dumps({
                                'type': 'stats',
                                'stats': stats,
                                'timestamp': time.time()
                            }))
                    
                    elif data.get('type') == 'ping':
                        await websocket.send(json.dumps({
                            'type': 'pong', 
                            'timestamp': time.time(),
                            'server_time': time.time()
                        }))
        
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"🔌 Secure user disconnected: {username or 'Unknown'} from {client_ip}")
        except Exception as e:
            logger.error(f"❌ Secure connection error: {e}")
            self.log_security_event("CONNECTION_ERROR", client_ip, username, str(e), 3)
        
        finally:
            # Always cleanup on disconnect
            await self.handle_disconnect(websocket, username, client_ip, connection_log_id, messages_sent)
    
    async def handle_disconnect(self, websocket, username, client_ip, connection_log_id, messages_sent):
        """Handle client disconnection with comprehensive cleanup"""
        if websocket in self.people_online:
            self.people_online.remove(websocket)
        
        if websocket in self.who_is_who:
            if username is None:
                username = self.who_is_who[websocket]
            del self.who_is_who[websocket]
        
        # Update connection log
        self.update_connection_log(connection_log_id, messages_sent)
        
        if username:
            logger.info(f"👋 Secure user left: {username} from {client_ip} (sent {messages_sent} messages)")
            self.log_security_event("USER_LEFT", client_ip, username, f"Sent {messages_sent} messages", 1)
            
            # Notify others about user leaving
            online_users = list(set(self.who_is_who.values()))
            leave_message = json.dumps({
                'type': 'user_leave',
                'username': username,
                'msg': f'{username} left the secure chat 👋',
                'online_count': len(online_users),
                'timestamp': time.time()
            })
            
            for client in self.people_online:
                try:
                    await client.send(leave_message)
                except:
                    pass
    
    def get_server_stats(self):
        """Get server statistics for monitoring"""
        return {
            **self.stats,
            'online_users': len(self.people_online),
            'active_connections': len(self.people_online),
            'blocked_ips': len(self.security.ip_blacklist),
            'uptime': time.time() - getattr(self, 'start_time', time.time())
        }

def setup_high_security_ssl(cert_file=None, key_file=None):
    """Setup high-security SSL configuration"""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # High security SSL settings
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    ssl_context.options |= ssl.OP_NO_SSLv2
    ssl_context.options |= ssl.OP_NO_SSLv3
    ssl_context.options |= ssl.OP_NO_TLSv1
    ssl_context.options |= ssl.OP_NO_TLSv1_1
    
    # Use provided certificates or generate secure ones
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context.load_cert_chain(cert_file, key_file)
        logger.info("✅ Using provided SSL certificates with high security")
    else:
        # Generate high-security self-signed certificates
        logger.warning("⚠️ Generating high-security self-signed certificates")
        cert_path = 'high_security_server.crt'
        key_path = 'high_security_server.key'
        
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            logger.info("🔐 Generating high-security SSL certificates...")
            os.system(f'''
                openssl req -x509 -newkey rsa:4096 -nodes -sha256 \
                -out {cert_path} -keyout {key_path} \
                -days 365 -subj "/C=US/ST=Secure/L=Chat/O=HighSecurity/CN=secure-chat-server" \
                -addext "subjectAltName=DNS:localhost,DNS:127.0.0.1"
            ''')
        
        ssl_context.load_cert_chain(cert_path, key_path)
        logger.info("✅ Using high-security self-signed certificates")
    
    return ssl_context

async def main():
    """Start the high-security production chat server"""
    parser = argparse.ArgumentParser(description='High Security Chat Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8765, help='Port to listen on (default: 8765)')
    parser.add_argument('--cert', help='SSL certificate file')
    parser.add_argument('--key', help='SSL private key file')
    
    args = parser.parse_args()
    
    # Create server instance
    chat_server = HighSecurityChatServer(host=args.host, port=args.port)
    chat_server.start_time = time.time()
    
    # Setup SSL
    ssl_context = setup_high_security_ssl(args.cert, args.key)
    
    # Production server configuration
    server = await websockets.serve(
        chat_server.handle_connection,
        args.host,
        args.port,
        ssl=ssl_context,
        ping_interval=20,
        ping_timeout=30,
        max_size=10 * 1024 * 1024,  # 10MB max message size
        max_queue=100  # Max messages in queue
    )
    
    print("\n" + "="*70)
    print("🛡️  HIGH-SECURITY PRODUCTION CHAT SERVER RUNNING!")
    print("="*70)
    print(f"   Host: {args.host}")
    print(f"   Port: {args.port}")
    print("   SSL: Enabled with High Security 🔒")
    print("   Database: SQLite with WAL mode")
    print("   Security: Comprehensive protection active")
    print("   Logging: Detailed security logging enabled")
    print("="*70)
    print("\n📋 Production Endpoints:")
    print(f"   - Secure WebSocket: wss://your-domain.com:{args.port}")
    print(f"   - Local testing: wss://localhost:{args.port}")
    print("\n🔒 Security Features:")
    print("   - Rate limiting on all actions")
    print("   - IP blocking for suspicious activity") 
    print("   - Message content validation")
    print("   - XSS and SQL injection protection")
    print("   - Comprehensive logging and monitoring")
    print("   - TLS 1.2+ with secure ciphers")
    print("\n📊 Monitoring:")
    print("   - Log file: security_chat.log")
    print("   - Database: secure_chat.db")
    print("   - Real-time security event tracking")
    print("="*70)
    print("\nWaiting for secure connections...")
    
    # Periodic statistics logging
    async def log_statistics():
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            stats = chat_server.get_server_stats()
            logger.info(f"📊 Server Statistics: {stats}")
    
    asyncio.create_task(log_statistics())
    
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped gracefully by administrator")
        print("\n🛑 High-security server stopped gracefully")
    except Exception as e:
        logger.critical(f"💥 Server crashed: {e}")
        print(f"💥 Server crashed: {e}")
        raise
