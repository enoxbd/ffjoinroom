import asyncio
import socket
import time
import threading
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Import authentication and packet functions
from JwtGen import (
    GeNeRaTeAccEss, EncRypTMajoRLoGin, MajorLogin, DecRypTMajoRLoGin,
    GetLoginData, DecRypTLoGinDaTa, xAuThSTarTuP
)
from Functions import RedZedJoinRomm

# ---------- Account client (online only) ----------
class RoomJoinerClient:
    def __init__(self, uid, password):
        self.uid = str(uid)
        self.password = password
        self.key = None
        self.iv = None
        self.auth_token = None
        self.online_sock = None
        self.running = False

    def _run_async(self, coro):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def full_auth(self):
        """Authenticate and get online server info."""
        try:
            open_id, access_token = self._run_async(GeNeRaTeAccEss(self.uid, self.password))
            if not open_id or not access_token:
                print(f"[-] {self.uid} Failed to get open_id/access_token")
                return False
            payload = self._run_async(EncRypTMajoRLoGin(open_id, access_token))
            login_res = self._run_async(MajorLogin(payload))
            if not login_res:
                print(f"[-] {self.uid} MajorLogin failed")
                return False
            dec = self._run_async(DecRypTMajoRLoGin(login_res))
            self.key = dec.key
            self.iv = dec.iv
            token = dec.token
            timestamp = dec.timestamp
            account_uid = dec.account_uid
            # Get ports
            login_data = self._run_async(GetLoginData(dec.url, payload, token))
            if not login_data:
                print(f"[-] {self.uid} GetLoginData failed")
                return False
            ports = self._run_async(DecRypTLoGinDaTa(login_data))
            online_ip, online_port = ports.Online_IP_Port.split(":")
            self.online_ip = online_ip
            self.online_port = int(online_port)
            # Generate final auth token
            self.auth_token = self._run_async(xAuThSTarTuP(
                int(account_uid), token, int(timestamp), self.key, self.iv
            ))
            return True
        except Exception as e:
            print(f"[-] {self.uid} Auth error: {e}")
            return False

    def connect_online(self):
        """Connect to online server and verify."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.online_ip, self.online_port))
            sock.send(bytes.fromhex(self.auth_token))
            resp = sock.recv(4096)
            if not resp:
                sock.close()
                return None
            print(f"[+] {self.uid} Online connected")
            return sock
        except Exception as e:
            print(f"[-] {self.uid} Socket error: {e}")
            return None

    def reader_thread(self, sock):
        """Keep connection alive by reading incoming data."""
        while self.running:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                # Optionally log or ignore
            except:
                break
        self.running = False

    def join_room(self, room_id, password=""):
        """Send join room packet."""
        if not self.online_sock:
            print(f"[-] {self.uid} Not connected")
            return False
        try:
            pkt = self._run_async(RedZedJoinRomm(room_id, password, self.key, self.iv))
            self.online_sock.send(pkt)
            print(f"[+] {self.uid} Join request sent to room {room_id}")
            return True
        except Exception as e:
            print(f"[-] {self.uid} Failed to send join packet: {e}")
            return False

    def start(self):
        """Full connection process."""
        if not self.full_auth():
            return False
        sock = self.connect_online()
        if not sock:
            return False
        self.online_sock = sock
        self.running = True
        threading.Thread(target=self.reader_thread, args=(sock,), daemon=True).start()
        return True

    def close(self):
        self.running = False
        if self.online_sock:
            try:
                self.online_sock.close()
            except:
                pass
            self.online_sock = None

# ---------- Load accounts from JSON file ----------
def load_accounts_from_json(filename="accounts.json", max_accounts=50):
    """Load accounts from JSON file format."""
    accounts = []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)
            
            # Handle both array and object formats
            if isinstance(data, list):
                account_list = data
            elif isinstance(data, dict) and "accounts" in data:
                account_list = data["accounts"]
            else:
                print(f"[!] Unknown JSON format in {filename}")
                return []
            
            for item in account_list[:max_accounts]:
                # Extract uid and password from JSON object
                uid = item.get("uid")
                password = item.get("password")
                
                if uid and password:
                    accounts.append((str(uid), password))
                else:
                    print(f"[!] Skipping invalid account entry: missing uid or password")
                    
    except FileNotFoundError:
        print(f"[!] File {filename} not found.")
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in {filename}: {e}")
    
    return accounts

# Alternative: Load from JSON file with more fields (for logging/debugging)
def load_accounts_from_json_detailed(filename="accounts.json", max_accounts=50):
    """Load accounts with additional info for logging."""
    accounts = []
    account_info = []
    
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)
            
            if isinstance(data, list):
                account_list = data
            elif isinstance(data, dict) and "accounts" in data:
                account_list = data["accounts"]
            else:
                print(f"[!] Unknown JSON format in {filename}")
                return [], []
            
            for item in account_list[:max_accounts]:
                uid = item.get("uid")
                password = item.get("password")
                
                if uid and password:
                    accounts.append((str(uid), password))
                    account_info.append({
                        "uid": uid,
                        "name": item.get("name", "Unknown"),
                        "region": item.get("region", "N/A"),
                        "account_id": item.get("account_id", "N/A")
                    })
                else:
                    print(f"[!] Skipping invalid account entry")
                    
    except FileNotFoundError:
        print(f"[!] File {filename} not found.")
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in {filename}: {e}")
    
    return accounts, account_info

# ---------- Main ----------
def main():
    print("=== Room Joiner Tool (JSON format) ===")
    
    # Load accounts from JSON file
    accounts = load_accounts_from_json("accounts.json", max_accounts=50)
    
    if not accounts:
        print("[!] No accounts loaded. Exiting.")
        return

    print(f"[*] Loaded {len(accounts)} accounts (max 50)")
    
    # Optional: Display loaded account summary
    print("\n[*] Loaded accounts:")
    for i, (uid, _) in enumerate(accounts[:10], 1):  # Show first 10
        print(f"    {i}. UID: {uid}")
    if len(accounts) > 10:
        print(f"    ... and {len(accounts) - 10} more")

    # Connect all accounts
    clients = []
    print("\n[*] Connecting accounts...")
    for uid, pwd in accounts:
        client = RoomJoinerClient(uid, pwd)
        if client.start():
            clients.append(client)
            print(f"[+] {uid} connected")
        else:
            print(f"[-] {uid} failed to connect")
        time.sleep(1)  # avoid rate limiting

    if not clients:
        print("[!] No accounts connected. Exiting.")
        return

    print(f"\n[*] {len(clients)} accounts online.\n")

    # Get room details
    room_id = input("Enter Room ID: ").strip()
    password = input("Enter Room Password (leave empty if none): ").strip()

    if not room_id:
        print("[!] Room ID required. Exiting.")
        return

    print(f"\n[*] Joining room {room_id} with {len(clients)} accounts...")
    for client in clients:
        client.join_room(room_id, password)
        time.sleep(0.5)  # slight delay between joins

    print("[*] All join requests sent.")
    print("[*] Press Ctrl+C to exit (connections will stay alive).")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Closing connections...")
        for client in clients:
            client.close()
        print("[*] Done.")

if __name__ == "__main__":
    main()