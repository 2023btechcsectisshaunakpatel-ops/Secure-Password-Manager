import sys
import json
import os
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Add backend directory to path
sys.path.append(str(Path(__file__).parent))

from database import init_db, get_db_connection
from auth import hash_password, verify_password, create_access_token, decode_access_token
from crypto import encrypt, decrypt
from pw_util import calculate_password_strength, generate_secure_password

class PasswordManagerAuthHandler(BaseHTTPRequestHandler):
    
    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def _get_authenticated_user(self):
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return None
        token = auth_header.split('Bearer ')[1]
        payload = decode_access_token(token)
        return payload

    def do_POST(self):
        parsed = urlparse(self.path)
        parsed_path = parsed.path
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        
        try:
            body = json.loads(post_data.decode('utf-8'))
        except Exception:
            self._send_json(400, {"detail": "Invalid JSON request body"})
            return

        if parsed_path == "/auth/register":
            email = str(body.get("email", "")).strip().lower()
            password = str(body.get("password", ""))

            if not email or "@" not in email:
                self._send_json(400, {"detail": "Invalid email address"})
                return
            if not password or len(password) < 6:
                self._send_json(400, {"detail": "Password must be at least 6 characters"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                conn.close()
                self._send_json(400, {"detail": "Email already registered"})
                return

            hashed_pwd = hash_password(password)
            cursor.execute("INSERT INTO users (email, hashed_password) VALUES (?, ?)", (email, hashed_pwd))
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()

            self._send_json(201, {
                "id": user_id,
                "email": email,
                "message": "User registered successfully"
            })
            return

        elif parsed_path == "/auth/login":
            email = str(body.get("email", "")).strip().lower()
            password = str(body.get("password", ""))

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, hashed_password FROM users WHERE email = ?", (email,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                self._send_json(401, {"detail": "Invalid email or password"})
                return

            user_id, user_email, hashed_pwd = row["id"], row["email"], row["hashed_password"]

            if not verify_password(password, hashed_pwd):
                self._send_json(401, {"detail": "Invalid email or password"})
                return

            access_token = create_access_token(data={"sub": user_email, "user_id": user_id})
            self._send_json(200, {
                "access_token": access_token,
                "token_type": "bearer"
            })
            return

        elif parsed_path == "/utils/password-strength":
            pwd = str(body.get("password", ""))
            result = calculate_password_strength(pwd)
            self._send_json(200, result)
            return

        elif parsed_path == "/utils/generate-password":
            length = int(body.get("length", 16))
            use_uppercase = bool(body.get("use_uppercase", True))
            use_lowercase = bool(body.get("use_lowercase", True))
            use_digits = bool(body.get("use_digits", True))
            use_symbols = bool(body.get("use_symbols", True))

            generated_pw = generate_secure_password(length, use_uppercase, use_lowercase, use_digits, use_symbols)
            strength_analysis = calculate_password_strength(generated_pw)

            self._send_json(200, {
                "password": generated_pw,
                "strength": strength_analysis
            })
            return

        elif parsed_path == "/entries":
            user = self._get_authenticated_user()
            if not user or "user_id" not in user:
                self._send_json(401, {"detail": "Authentication required"})
                return

            site_name = str(body.get("site_name", "")).strip()
            site_username = str(body.get("site_username", "")).strip()
            raw_password = str(body.get("password", ""))

            if not site_name or not site_username or not raw_password:
                self._send_json(400, {"detail": "site_name, site_username, and password are required"})
                return

            # Encrypt site password using AES-256
            encrypted_password, nonce = encrypt(raw_password)

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO entries (user_id, site_name, site_username, encrypted_password, nonce)
                VALUES (?, ?, ?, ?, ?)
            """, (user["user_id"], site_name, site_username, encrypted_password, nonce))
            entry_id = cursor.lastrowid
            conn.commit()

            cursor.execute("SELECT created_at, updated_at FROM entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            conn.close()

            self._send_json(201, {
                "id": entry_id,
                "site_name": site_name,
                "site_username": site_username,
                "masked_password": "••••••••",
                "created_at": str(row["created_at"]) if row else None,
                "updated_at": str(row["updated_at"]) if row else None
            })
            return

        else:
            self._send_json(404, {"detail": "Not found"})

    def do_GET(self):
        parsed = urlparse(self.path)
        parsed_path = parsed.path
        query_params = parse_qs(parsed.query)

        if parsed_path == "/auth/me":
            user = self._get_authenticated_user()
            if not user:
                self._send_json(401, {"detail": "Invalid or expired authentication token"})
                return
            self._send_json(200, {"user": user})
            return

        elif parsed_path == "/entries":
            user = self._get_authenticated_user()
            if not user or "user_id" not in user:
                self._send_json(401, {"detail": "Authentication required"})
                return

            search_query = query_params.get("q", [""])[0].strip().lower()

            conn = get_db_connection()
            cursor = conn.cursor()

            if search_query:
                cursor.execute("""
                    SELECT id, site_name, site_username, created_at, updated_at
                    FROM entries
                    WHERE user_id = ? AND (LOWER(site_name) LIKE ? OR LOWER(site_username) LIKE ?)
                    ORDER BY id DESC
                """, (user["user_id"], f"%{search_query}%", f"%{search_query}%"))
            else:
                cursor.execute("""
                    SELECT id, site_name, site_username, created_at, updated_at
                    FROM entries
                    WHERE user_id = ?
                    ORDER BY id DESC
                """, (user["user_id"],))

            rows = cursor.fetchall()
            conn.close()

            entries = []
            for r in rows:
                entries.append({
                    "id": r["id"],
                    "site_name": r["site_name"],
                    "site_username": r["site_username"],
                    "masked_password": "••••••••",
                    "created_at": str(r["created_at"]),
                    "updated_at": str(r["updated_at"])
                })

            self._send_json(200, entries)
            return

        elif parsed_path.startswith("/entries/"):
            user = self._get_authenticated_user()
            if not user or "user_id" not in user:
                self._send_json(401, {"detail": "Authentication required"})
                return

            try:
                entry_id = int(parsed_path.split("/entries/")[1])
            except ValueError:
                self._send_json(400, {"detail": "Invalid entry ID"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, site_name, site_username, encrypted_password, nonce, created_at, updated_at
                FROM entries
                WHERE id = ? AND user_id = ?
            """, (entry_id, user["user_id"]))
            row = cursor.fetchone()
            conn.close()

            if not row:
                self._send_json(404, {"detail": "Entry not found or access denied"})
                return

            # Decrypt stored site password
            decrypted_password = decrypt(row["encrypted_password"], row["nonce"])

            self._send_json(200, {
                "id": row["id"],
                "site_name": row["site_name"],
                "site_username": row["site_username"],
                "password": decrypted_password,
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"])
            })
            return

        self._send_json(404, {"detail": "Not found"})

    def do_PUT(self):
        parsed_path = urlparse(self.path).path
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'

        try:
            body = json.loads(post_data.decode('utf-8'))
        except Exception:
            self._send_json(400, {"detail": "Invalid JSON request body"})
            return

        if parsed_path.startswith("/entries/"):
            user = self._get_authenticated_user()
            if not user or "user_id" not in user:
                self._send_json(401, {"detail": "Authentication required"})
                return

            try:
                entry_id = int(parsed_path.split("/entries/")[1])
            except ValueError:
                self._send_json(400, {"detail": "Invalid entry ID"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM entries WHERE id = ? AND user_id = ?", (entry_id, user["user_id"]))
            if not cursor.fetchone():
                conn.close()
                self._send_json(404, {"detail": "Entry not found or access denied"})
                return

            site_name = body.get("site_name")
            site_username = body.get("site_username")
            raw_password = body.get("password")

            updates = []
            params = []

            if site_name is not None and str(site_name).strip():
                updates.append("site_name = ?")
                params.append(str(site_name).strip())

            if site_username is not None and str(site_username).strip():
                updates.append("site_username = ?")
                params.append(str(site_username).strip())

            if raw_password is not None and str(raw_password):
                enc_pwd, nonce = encrypt(str(raw_password))
                updates.append("encrypted_password = ?")
                params.append(enc_pwd)
                updates.append("nonce = ?")
                params.append(nonce)

            if not updates:
                conn.close()
                self._send_json(400, {"detail": "No fields to update"})
                return

            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(entry_id)
            params.append(user["user_id"])

            query = f"UPDATE entries SET {', '.join(updates)} WHERE id = ? AND user_id = ?"
            cursor.execute(query, tuple(params))
            conn.commit()

            cursor.execute("SELECT id, site_name, site_username, created_at, updated_at FROM entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            conn.close()

            self._send_json(200, {
                "id": row["id"],
                "site_name": row["site_name"],
                "site_username": row["site_username"],
                "masked_password": "••••••••",
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"])
            })
            return

        self._send_json(404, {"detail": "Not found"})

    def do_DELETE(self):
        parsed_path = urlparse(self.path).path

        if parsed_path.startswith("/entries/"):
            user = self._get_authenticated_user()
            if not user or "user_id" not in user:
                self._send_json(401, {"detail": "Authentication required"})
                return

            try:
                entry_id = int(parsed_path.split("/entries/")[1])
            except ValueError:
                self._send_json(400, {"detail": "Invalid entry ID"})
                return

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM entries WHERE id = ? AND user_id = ?", (entry_id, user["user_id"]))
            rows_affected = cursor.rowcount
            conn.commit()
            conn.close()

            if rows_affected == 0:
                self._send_json(404, {"detail": "Entry not found or access denied"})
                return

            self._send_json(200, {"message": f"Entry {entry_id} deleted successfully"})
            return

        self._send_json(404, {"detail": "Not found"})

def run_server(port=8000):
    init_db()
    server_address = ('', port)
    httpd = HTTPServer(server_address, PasswordManagerAuthHandler)
    print(f"🔒 Secure Password Manager Auth Server running on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port)
