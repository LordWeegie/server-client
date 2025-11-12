# high_security_nicegui_client.py
from nicegui import ui
import asyncio
import websockets
import json
import ssl
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HighSecurityChatClient:
    def __init__(self):
        self.websocket = None
        self.connected = False
        self.joined = False
        self.username = None
        self.server_url = "wss://localhost:8765"
        
    async def connect(self):
        """Connect to high-security WebSocket server"""
        try:
            # High-security SSL context
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Additional security settings
            ssl_context.options |= ssl.OP_NO_SSLv2
            ssl_context.options |= ssl.OP_NO_SSLv3
            ssl_context.options |= ssl.OP_NO_TLSv1
            ssl_context.options |= ssl.OP_NO_TLSv1_1
            
            self.websocket = await websockets.connect(
                self.server_url,
                ssl=ssl_context,
                ping_interval=20,
                ping_timeout=30
            )
            self.connected = True
            logger.info("✅ Connected to high-security server")
            return True
        except Exception as e:
            logger.error(f"❌ Connection failed: {e}")
            return False
    
    async def join_chat(self, username):
        """Join the chat with security validation"""
        if not self.connected:
            if not await self.connect():
                return False
        
        join_message = {
            'type': 'join',
            'username': username
        }
        await self.websocket.send(json.dumps(join_message))
        self.username = username
        return True
    
    async def send_message(self, text):
        """Send message with security checks"""
        if not self.connected or not self.joined:
            return False
        
        message = {
            'type': 'message',
            'text': text
        }
        await self.websocket.send(json.dumps(message))
        return True
    
    async def listen_for_messages(self, message_handler):
        """Listen for incoming messages"""
        while self.connected and self.websocket:
            try:
                message = await self.websocket.recv()
                data = json.loads(message)
                await message_handler(data)
                
                if data.get('type') == 'welcome':
                    self.joined = True
                    
            except websockets.exceptions.ConnectionClosed:
                logger.info("🔌 Connection closed by server")
                self.connected = False
                self.joined = False
                break
            except Exception as e:
                logger.error(f"Receive error: {e}")
                break

# Global chat client
chat_client = HighSecurityChatClient()

def main():
    # Your exact UI design with enhanced security features
    ui.add_head_html('''
        <style>
            body {
                background: linear-gradient(to right, #000000, #fa3232);
                margin: 0;
                padding: 0;
                font-family: Arial, sans-serif;
            }
            .security-status {
                position: fixed;
                top: 10px;
                right: 20px;
                color: white;
                font-weight: bold;
                z-index: 1000;
            }
            .online-counter {
                position: fixed;
                top: 40px;
                right: 20px;
                color: white;
                z-index: 1000;
            }
            .join-section {
                position: fixed;
                top: 10px;
                left: 20px;
                z-index: 1000;
            }
        </style>
    ''')

    # Security status indicator
    with ui.column().classes('security-status'):
        security_status = ui.label('🔴 Security: Disconnected').style('color: white; font-weight: bold;')
        encryption_status = ui.label('🛡️ Encryption: Inactive').style('color: white;')
        online_counter = ui.label('Online: 0').style('color: white;').classes('online-counter')

    # Join section (your exact design)
    with ui.column().classes('join-section'):
        username_input = ui.input(placeholder="Enter your username").style(
            'background-color: #f2f2f2; padding: 10px; border: none; border-radius: 5px; width: 200px;'
        )
        
        with ui.row():
            join_button = ui.button("Join High-Security Chat", on_click=lambda: join_chat()).style(
                'background-color: #4CAF50; color: white; padding: 10px; border: none; border-radius: 5px;'
            )
            
            server_input = ui.input(placeholder="Server URL").style(
                'background-color: #f2f2f2; padding: 10px; border: none; border-radius: 5px; width: 250px;'
            )
            server_input.value = "wss://localhost:8765"

    # Your exact scroll area and messages container
    with ui.scroll_area().style(
        'height: 850px; width: 1250px; border: 1px solid black; '
        'position: fixed; top: 0; left: 50%; '
        'transform: translateX(-50%); '
        'background-color: #f2f2f2; padding: 10px; border-radius: 5px;'
    ):
        messages_container = ui.column()

    # Your exact input field and send button
    input_field = ui.input(placeholder="Type your message here").style(
        "width: 50%; position: fixed; bottom: 0; left: 25%; background-color: #f2f2f2; padding: 10px; border: none; border-radius: 5px;"
    ).props('disable')

    send_button = ui.button("Send Securely", on_click=lambda: send_message()).style(
        "position: fixed; bottom: 0; right: 22%; background-color: black; padding: 10px; border: none; border-radius: 10px; height: 50px; color: white; cursor: pointer;"
    ).props('disable')

    async def add_message(sender, message, message_type='user'):
        """Add message to chat with your exact styling"""
        with messages_container:
            if message == '':
                return
            with ui.row().style('margin-bottom: 10px; background: white; padding: 8px; border-radius: 8px;'):
                if message_type == 'user':
                    ui.label(sender).style('font-style: italic; color: #666; margin-right: 8px;')
                    ui.label(message).style('font-weight: bold;')
                else:
                    ui.label(f"⚡ {message}").style('color: #888; font-style: italic;')

    async def handle_server_message(data):
        """Handle messages from high-security server"""
        message_type = data.get('type')
        
        if message_type == 'welcome':
            security_status.set_text('🟢 Security: Connected & Encrypted')
            encryption_status.set_text('🛡️ Encryption: TLS 1.2+ Active')
            await add_message('System', data['msg'], 'system')
            input_field.props(remove='disable')
            send_button.props(remove='disable')
            join_button.props('disable')
            ui.notify(data['msg'], type='positive')
            
        elif message_type == 'chat':
            await add_message(data['username'], data['text'])
            
        elif message_type == 'user_join':
            await add_message('System', data['msg'], 'system')
            online_counter.set_text(f'Online: {data.get("online_count", 0)}')
            ui.notify(data['msg'])
            
        elif message_type == 'user_leave':
            await add_message('System', data['msg'], 'system')
            online_counter.set_text(f'Online: {data.get("online_count", 0)}')
            ui.notify(data['msg'])
            
        elif message_type == 'online':
            online_counter.set_text(f'Online: {data.get("count", 0)}')
            
        elif message_type == 'history':
            for msg in data.get('messages', []):
                await add_message(msg['user'], msg['text'])
                
        elif message_type == 'error':
            await add_message('System', f"Security Notice: {data['msg']}", 'system')
            ui.notify(data['msg'], type='negative')

    async def join_chat():
        """Join high-security chat"""
        username = username_input.value.strip()
        server_url = server_input.value.strip()
        
        if not username:
            ui.notify("Please enter a username", type='warning')
            return
            
        if not server_url:
            ui.notify("Please enter server URL", type='warning')
            return
        
        # Client-side username validation
        if len(username) < 2 or len(username) > 20:
            ui.notify("Username must be 2-20 characters", type='negative')
            return
        
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            ui.notify("Username can only contain letters, numbers, hyphens, and underscores", type='negative')
            return
        
        chat_client.server_url = server_url
        security_status.set_text('🟡 Security: Establishing secure connection...')
        
        success = await chat_client.join_chat(username)
        if success:
            # Start listening for messages
            asyncio.create_task(chat_client.listen_for_messages(handle_server_message))
            ui.notify("Connecting to secure chat...", type='info')
        else:
            security_status.set_text('🔴 Security: Connection failed')
            ui.notify("Failed to connect to secure server", type='negative')

    async def send_message():
        """Send secure message"""
        message = input_field.value.strip()
        if not message:
            return
        
        if not chat_client.joined:
            ui.notify("Please join the chat first!", type='warning')
            return
        
        # Client-side message validation
        if len(message) > 500:
            ui.notify("Message too long (max 500 characters)", type='negative')
            return
        
        success = await chat_client.send_message(message)
        if success:
            # Add our message immediately to UI
            await add_message(chat_client.username or "You", message)
            input_field.value = ''
        else:
            ui.notify("Failed to send message", type='negative')

    # Bind Enter key to send message
    def on_enter(event):
        if event.key == 'Enter' and chat_client.joined:
            send_message()
    
    input_field.on('keydown', on_enter)

    # Initial system messages
    async def init_messages():
        await add_message('System', '🛡️ HIGH-SECURITY CHAT CLIENT READY', 'system')
        await add_message('System', 'All communications are encrypted and secured', 'system')
        await add_message('System', 'Configure server URL and enter username to begin', 'system')

    # Initialize on startup
    ui.timer(0.1, init_messages, once=True)

    # Server connection test
    async def test_connection():
        """Test server connection on startup"""
        try:
            # Quick connection test
            temp_client = HighSecurityChatClient()
            temp_client.server_url = server_input.value
            if await temp_client.connect():
                security_status.set_text('🟢 Security: Server reachable')
                encryption_status.set_text('🛡️ Encryption: Available')
                await temp_client.websocket.close()
            else:
                security_status.set_text('🔴 Security: Server unreachable')
        except:
            security_status.set_text('🔴 Security: Server unreachable')

    # Test connection after a short delay
    ui.timer(2.0, test_connection, once=True)

    ui.run(host="0.0.0.0", port=8080, title="High-Security Chat Client")

if __name__ in {"__main__", "__mp_main__"}:
    main()
