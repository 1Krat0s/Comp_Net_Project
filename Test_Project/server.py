import hashlib
import hmac
import json
import os
import selectors
import socket
import tempfile
import threading
import time
from pathlib import Path

from analysis import NetworkAnalyzer

IP = "10.200.102.109"
PORT = 4500
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_PATH = "server"

# Additional listener for authenticated JSON file-sharing clients.
JSON_PORT = 4450
JSON_ADDR = (IP, JSON_PORT)
BUFFER_SIZE = 64 * 1024
MAX_MESSAGE_SIZE = 64 * 1024
SERVER_STORAGE_PATH = "server_data"
STORAGE_ROOT = Path(SERVER_STORAGE_PATH).resolve()
INDEX_PATH = STORAGE_ROOT / ".upload_index.json"

PREFIX_MAPPING = {
    ".txt": "TS",
    ".wav": "AS",
    ".mp3": "AS",
    ".mp4": "VS",
    ".mkv": "VS",
}

# Demo-only accounts. A password hash sent without TLS can be replayed;
# use TLS and per-user password hashing for a real public-facing system.
PASSWORD_SALT = "CNT3004_FL26_SECURE_SALT"
USER_CREDENTIALS = {
    "admin": hashlib.sha256((PASSWORD_SALT + "AdminPass123!").encode()).hexdigest(),
    "student1": hashlib.sha256((PASSWORD_SALT + "NetPass2026").encode()).hexdigest(),
    "student2": hashlib.sha256((PASSWORD_SALT + "CloudFileShare!").encode()).hexdigest(),
}

analyzer = NetworkAnalyzer("network_stats.csv")


class ServerState:
    """Connection tracking, file reservations, and persistent original-name mapping."""

    def __init__(self):
        self.clients = {}
        self.clients_lock = threading.Lock()
        self.storage_lock = threading.RLock()
        self.locked_files = set()
        self.pending_uploads = set()
        self.file_index = {}
        if INDEX_PATH.is_file():
            try:
                with INDEX_PATH.open("r", encoding=FORMAT) as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    self.file_index = loaded
            except (OSError, ValueError) as error:
                print(f"[INDEX] Could not load filename index: {error}")

    def register(self, addr, conn):
        with self.clients_lock:
            self.clients[addr] = {"socket": conn, "user": None, "connected_at": time.time()}
            return len(self.clients)

    def set_user(self, addr, username):
        with self.clients_lock:
            if addr in self.clients:
                self.clients[addr]["user"] = username

    def unregister(self, addr):
        with self.clients_lock:
            self.clients.pop(addr, None)
            return len(self.clients)

    def save_index(self):
        """Atomically save original-name -> logical-name mappings (storage lock held)."""
        STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".index-", dir=STORAGE_ROOT)
        try:
            with os.fdopen(fd, "w", encoding=FORMAT) as f:
                json.dump(self.file_index, f, indent=2)
            os.replace(name, INDEX_PATH)
        finally:
            if os.path.exists(name):
                os.remove(name)

    def acquire(self, path):
        with self.storage_lock:
            if path in self.locked_files:
                return False
            self.locked_files.add(path)
            return True

    def release(self, path):
        with self.storage_lock:
            self.locked_files.discard(path)


state = ServerState()


def get_safe_path(relative_path=""):
    """Return a path inside storage; block absolute paths, traversal, and symlinks out."""
    if not isinstance(relative_path, str) or "\x00" in relative_path:
        raise ValueError("Invalid path")
    normalized = relative_path.replace("\\", "/")
    if normalized.startswith("/") or ":" in normalized.split("/")[0]:
        raise ValueError("Absolute paths are not allowed")
    if ".." in normalized.split("/"):
        raise ValueError("Parent directory traversal is not allowed")
    target = (STORAGE_ROOT / normalized).resolve()
    if target != STORAGE_ROOT and STORAGE_ROOT not in target.parents:
        raise PermissionError("Path must remain within server storage")
    return target


def get_filename(value):
    if (not isinstance(value, str) or not value or value in (".", "..")
            or "/" in value or "\\" in value or "\x00" in value
            or value.startswith(".upload-") or value == INDEX_PATH.name):
        raise ValueError("Invalid filename; supply a filename, not a path")
    return value


def index_key(folder, filename):
    return (folder.relative_to(STORAGE_ROOT) / filename).as_posix()


def new_logical_name(filename, folder):
    ext = Path(filename).suffix.lower()
    prefix = PREFIX_MAPPING.get(ext, "FS")
    counter = 1
    while True:
        candidate = folder / f"{prefix}{counter:03d}{ext}"
        if not candidate.exists() and candidate not in state.locked_files:
            return candidate
        counter += 1


def resolve_file(folder, filename):
    """Resolve a logical stored filename, or the original upload name."""
    direct = get_safe_path((folder / filename).relative_to(STORAGE_ROOT).as_posix())
    if direct.is_file():
        return direct
    with state.storage_lock:
        mapped = state.file_index.get(index_key(folder, filename))
    if mapped:
        target = get_safe_path(mapped)
        if target.parent == folder and target.is_file():
            return target
    return direct


def calculate_sha256(filepath):
    checksum = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(BUFFER_SIZE), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def send_json(sock, payload):
    sock.sendall((json.dumps(payload) + "\n").encode(FORMAT))


def recv_json(reader):
    """Use the SAME buffered reader for JSON AND binary transfers.

    Mixing socket.recv() and an independent buffered reader can lose bytes
    when a control message and the beginning of a file arrive together.
    """
    line = reader.readline(MAX_MESSAGE_SIZE + 1)
    if not line:
        return None
    if len(line) > MAX_MESSAGE_SIZE or not line.endswith(b"\n"):
        raise ValueError("Invalid or oversized JSON message")
    try:
        result = json.loads(line.decode(FORMAT))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid JSON message") from error
    if not isinstance(result, dict):
        raise ValueError("JSON message must be an object")
    return result


def record_response(client_id, operation, started, status="success"):
    analyzer.record_response(
        source="server", client_id=client_id,
        operation=operation.lower(),
        duration_seconds=time.perf_counter() - started, status=status,
    )


def respond(conn, client_id, operation, started, status, **details):
    send_json(conn, {"status": status, **details})
    record_response(client_id, operation, started,
                    "success" if status not in ("ERROR", "EXISTS") else "error")


def reserve_upload(folder, filename, overwrite):
    """Reserve a unique destination without races with simultaneous clients."""
    key = index_key(folder, filename)
    with state.storage_lock:
        if key in state.pending_uploads:
            return "LOCKED", None, key
        stored = state.file_index.get(key)
        old_path = get_safe_path(stored) if stored else folder / filename
        if stored and not old_path.is_file():
            old_path = folder / filename
        if old_path.exists():
            if not old_path.is_file():
                raise ValueError("Destination is not a file")
            if not overwrite:
                return "EXISTS", old_path, key
            dest = old_path
        else:
            dest = new_logical_name(filename, folder)
        if dest in state.locked_files:
            return "LOCKED", dest, key
        state.locked_files.add(dest)
        state.pending_uploads.add(key)
        return "READY", dest, key


def release_upload(dest, key):
    with state.storage_lock:
        state.locked_files.discard(dest)
        state.pending_uploads.discard(key)


def upload_file(conn, reader, req, addr, started):
    client_id = f"{addr[0]}:{addr[1]}"
    filename = get_filename(req.get("filename"))
    folder = get_safe_path(req.get("subfolder", ""))
    size = req.get("size")
    if type(size) is not int or size < 0:
        raise ValueError("Upload size must be a nonnegative integer")
    if type(req.get("overwrite", False)) is not bool:
        raise ValueError("Overwrite must be true or false")
    overwrite = req.get("overwrite", False)
    expected_hash = req.get("sha256")
    if expected_hash is not None and (not isinstance(expected_hash, str)
                                      or len(expected_hash) != 64
                                      or any(c not in "0123456789abcdefABCDEF" for c in expected_hash)):
        raise ValueError("Invalid SHA-256 checksum")
    folder.mkdir(parents=True, exist_ok=True)
    if not folder.is_dir():
        raise ValueError("Upload destination must be a directory")

    status, destination, key = reserve_upload(folder, filename, overwrite)
    if status == "EXISTS":
        respond(conn, client_id, "UPLOAD", started, "EXISTS",
                message=f"'{filename}' already exists. Confirm overwrite (yes/no).",
                assigned_name=destination.name)
        return
    if status == "LOCKED":
        respond(conn, client_id, "UPLOAD", started, "ERROR",
                message="File is currently being processed by another client")
        return

    temporary = None
    received = 0
    began = None
    succeeded = False
    try:
        fd, temporary = tempfile.mkstemp(prefix=".upload-", suffix=".part", dir=folder)
        respond(conn, client_id, "UPLOAD", started, "READY", assigned_name=destination.name)
        checksum = hashlib.sha256()
        began = time.perf_counter()
        with os.fdopen(fd, "wb") as output:
            while received < size:
                chunk = reader.read(min(BUFFER_SIZE, size - received))
                if not chunk:
                    raise ConnectionError("Client disconnected during upload")
                output.write(chunk)
                checksum.update(chunk)
                received += len(chunk)
        if expected_hash is not None and not hmac.compare_digest(checksum.hexdigest(),
                                                                  expected_hash.lower()):
            send_json(conn, {"status": "ERROR", "message": "Upload SHA-256 mismatch"})
            return

        os.replace(temporary, destination)
        temporary = None
        with state.storage_lock:
            state.file_index[key] = destination.relative_to(STORAGE_ROOT).as_posix()
            state.save_index()
        elapsed = time.perf_counter() - began
        succeeded = True
        send_json(conn, {
            "status": "SUCCESS", "message": f"Uploaded '{filename}' as '{destination.name}'",
            "assigned_name": destination.name, "size_bytes": received,
            "sha256": checksum.hexdigest(),
            "duration_seconds": round(elapsed, 4),
            "transfer_rate_mbs": round(received / 1_000_000 / elapsed, 3) if elapsed else 0,
        })
    finally:
        if temporary and os.path.exists(temporary):
            os.remove(temporary)
        release_upload(destination, key)
        if began is not None:
            analyzer.record_transfer(
                source="server", client_id=client_id, operation="upload",
                filename=destination.name, bytes_transferred=received,
                duration_seconds=time.perf_counter() - began,
                status="success" if succeeded else "error",
            )


def download_file(conn, req, addr, started):
    client_id = f"{addr[0]}:{addr[1]}"
    filename = get_filename(req.get("filename"))
    folder = get_safe_path(req.get("subfolder", ""))
    offset = req.get("offset", 0)
    if type(offset) is not int or offset < 0:
        raise ValueError("Download offset must be a nonnegative integer")
    filepath = resolve_file(folder, filename)
    if not filepath.is_file():
        respond(conn, client_id, "DOWNLOAD", started, "ERROR",
                message=f"File '{filename}' does not exist")
        return
    if not state.acquire(filepath):
        respond(conn, client_id, "DOWNLOAD", started, "ERROR",
                message="File is currently locked or in use")
        return

    sent = 0
    began = None
    succeeded = False
    try:
        total_size = filepath.stat().st_size
        if offset > total_size:
            respond(conn, client_id, "DOWNLOAD", started, "ERROR",
                    message="Resume offset exceeds file size")
            return
        digest = calculate_sha256(filepath)
        respond(conn, client_id, "DOWNLOAD", started, "READY",
                total_size=total_size, sending_bytes=total_size - offset,
                sha256=digest, filename=filepath.name)
        began = time.perf_counter()
        with filepath.open("rb") as source:
            source.seek(offset)
            while True:
                chunk = source.read(BUFFER_SIZE)
                if not chunk:
                    break
                conn.sendall(chunk)
                sent += len(chunk)
        succeeded = True
    finally:
        state.release(filepath)
        if began is not None:
            analyzer.record_transfer(
                source="server", client_id=client_id, operation="download",
                filename=filepath.name, bytes_transferred=sent,
                duration_seconds=time.perf_counter() - began,
                status="success" if succeeded else "error",
            )


def handle_client(conn, addr):
    client_id = f"{addr[0]}:{addr[1]}"
    count = state.register(addr, conn)
    print(f"[NEW CONNECTION] {client_id} | Active clients: {count}")
    username = None
    try:
        conn.settimeout(300)
        with conn.makefile("rb") as reader:
            send_json(conn, {"status": "OK", "message": "Connected to Cloud Server. Authenticate with AUTH."})
            while True:
                request = recv_json(reader)
                if request is None:
                    break
                cmd = request.get("command", "")
                if not isinstance(cmd, str):
                    raise ValueError("Command must be a string")
                cmd = cmd.strip().upper()
                started = time.perf_counter()

                try:
                    if cmd == "AUTH":
                        name = request.get("username", "")
                        password_hash = request.get("password_hash", "")
                        expected = USER_CREDENTIALS.get(name) if isinstance(name, str) else None
                        if expected and isinstance(password_hash, str) and hmac.compare_digest(expected, password_hash):
                            username = name
                            state.set_user(addr, name)
                            respond(conn, client_id, cmd, started, "SUCCESS", message=f"Welcome, {name}!")
                            print(f"[AUTH] {client_id}: {name}")
                        else:
                            username = None
                            state.set_user(addr, None)
                            respond(conn, client_id, cmd, started, "ERROR", message="Invalid username or password")
                        continue

                    if cmd in ("LOGOUT", "DISCONNECT"):
                        respond(conn, client_id, cmd, started, "DISCONNECTED", message="Logged out successfully")
                        break
                    if not username:
                        respond(conn, client_id, cmd, started, "ERROR", message="Authentication required")
                        continue

                    if cmd == "HELP":
                        respond(conn, client_id, cmd, started, "SUCCESS",
                                commands=["AUTH", "UPLOAD", "DOWNLOAD", "DELETE", "DIR", "SUBFOLDER", "METRIC", "LOGOUT"])
                    elif cmd == "DIR":
                        folder = get_safe_path(request.get("path", ""))
                        if not folder.is_dir():
                            raise ValueError("Directory not found")
                        entries = []
                        for entry in sorted(folder.iterdir()):
                            if entry.name == INDEX_PATH.name or entry.name.startswith((".upload-", ".index-")):
                                continue
                            entries.append({
                                "name": entry.name,
                                "type": "directory" if entry.is_dir() else "file",
                                "size_bytes": 0 if entry.is_dir() else entry.stat().st_size,
                            })
                        respond(conn, client_id, cmd, started, "SUCCESS", entries=entries)
                    elif cmd == "SUBFOLDER":
                        action = request.get("action", "")
                        folder = get_safe_path(request.get("path", ""))
                        if folder == STORAGE_ROOT:
                            raise ValueError("Cannot create or remove the storage root")
                        if action == "create":
                            folder.mkdir(parents=True, exist_ok=False)
                            message = f"Created directory '{request['path']}'"
                        elif action == "delete":
                            folder.rmdir()  # Rejects nonempty directories.
                            with state.storage_lock:
                                prefix = folder.relative_to(STORAGE_ROOT).as_posix() + "/"
                                state.file_index = {
                                    k: v for k, v in state.file_index.items()
                                    if not k.startswith(prefix) and not v.startswith(prefix)
                                }
                                state.save_index()
                            message = f"Deleted directory '{request['path']}'"
                        else:
                            raise ValueError("Action must be 'create' or 'delete'")
                        respond(conn, client_id, cmd, started, "SUCCESS", message=message)
                    elif cmd == "UPLOAD":
                        upload_file(conn, reader, request, addr, started)
                    elif cmd == "DOWNLOAD":
                        download_file(conn, request, addr, started)
                    elif cmd in ("DELETE", "DEL"):
                        filename = get_filename(request.get("filename"))
                        folder = get_safe_path(request.get("subfolder", ""))
                        target = resolve_file(folder, filename)
                        if not target.is_file():
                            raise ValueError(f"File '{filename}' does not exist")
                        if not state.acquire(target):
                            raise ValueError("File is currently being processed by another client")
                        try:
                            target.unlink()
                            with state.storage_lock:
                                relative = target.relative_to(STORAGE_ROOT).as_posix()
                                state.file_index = {k: v for k, v in state.file_index.items() if v != relative}
                                state.save_index()
                        finally:
                            state.release(target)
                        respond(conn, client_id, cmd, started, "SUCCESS", message=f"Deleted '{target.name}'")
                    elif cmd == "METRIC":
                        analyzer.record_client_metric(request, client_id)
                        send_json(conn, {"status": "SUCCESS", "message": "Metric saved"})
                    else:
                        respond(conn, client_id, cmd or "UNKNOWN", started, "ERROR",
                                message=f"Unknown command: '{cmd}'")
                except ConnectionError:
                    # EOF mid-transfer cannot be recovered on this connection.
                    # Do not send a new control response after the binary framing broke.
                    raise
                except (ValueError, PermissionError, OSError) as error:
                    print(f"[COMMAND ERROR] {client_id} | {cmd}: {error}")
                    respond(conn, client_id, cmd or "UNKNOWN", started, "ERROR", message=str(error))

    except (ConnectionError, OSError, ValueError) as error:
        print(f"[CLIENT ERROR] {client_id}: {error}")
    finally:
        count = state.unregister(addr)
        conn.close()
        print(f"[DISCONNECTED] {client_id} | Active clients: {count}")


def send_legacy(conn, status, message):
    """Reply in the format expected by client_1.py and client_2.py."""
    conn.sendall(f"{status}@{str(message).replace('@', ' ')}".encode(FORMAT))


def handle_legacy_client(conn, addr):
    """Keep the original plain-text TASK, HELP, METRIC, LOGOUT clients working.

    The old clients send one bare command at a time and wait for a response;
    this handler deliberately does not enable unauthenticated file operations.
    Modern file uploads/downloads remain on the authenticated JSON listener.
    """
    client_id = f"{addr[0]}:{addr[1]}"
    count = state.register(addr, conn)
    print(f"[LEGACY CONNECTION] {client_id} | Active clients: {count}")
    try:
        conn.settimeout(300)
        send_legacy(conn, "OK", "Welcome to the server")
        while True:
            message = conn.recv(SIZE)
            if not message:
                break
            try:
                parts = message.decode(FORMAT).strip().split("@")
            except UnicodeDecodeError:
                send_legacy(conn, "ERROR", "Invalid message encoding")
                continue
            cmd = parts[0].strip().upper()
            started = time.perf_counter()

            if cmd in ("LOGOUT", "DISCONNECT"):
                # Older clients close immediately after sending LOGOUT.
                try:
                    send_legacy(conn, "DISCONNECTED", "Logged out successfully.")
                except OSError:
                    pass
                break
            if cmd == "TASK":
                send_legacy(conn, "OK", "LOGOUT from the server.")
                record_response(client_id, cmd, started)
            elif cmd == "HELP":
                send_legacy(conn, "OK", "Available commands: HELP, TASK, METRIC, LOGOUT")
                record_response(client_id, cmd, started)
            elif cmd == "METRIC":
                try:
                    if len(parts) < 4:
                        raise ValueError("Incomplete metric")
                    metric_type = parts[1].strip().upper()
                    operation = parts[2].strip().lower()
                    if metric_type == "TRANSFER" and len(parts) == 6:
                        analyzer.record_transfer(
                            source="client", client_id=client_id,
                            operation=operation, filename=parts[3],
                            bytes_transferred=int(parts[4]),
                            duration_seconds=float(parts[5]),
                        )
                    elif metric_type == "RESPONSE" and len(parts) == 4:
                        analyzer.record_response(
                            source="client", client_id=client_id,
                            operation=operation, duration_seconds=float(parts[3]),
                        )
                    else:
                        raise ValueError("Invalid metric format")
                    send_legacy(conn, "OK", "Metric saved")
                except (ValueError, OverflowError, KeyError) as error:
                    print(f"[ANALYSIS ERROR] {client_id}: {error}")
                    send_legacy(conn, "ERROR", "Invalid metric data")
            else:
                send_legacy(conn, "ERROR", "Unknown command")
                record_response(client_id, cmd or "UNKNOWN", started, "error")
    except (ConnectionError, OSError) as error:
        print(f"[LEGACY CLIENT ERROR] {client_id}: {error}")
    finally:
        count = state.unregister(addr)
        conn.close()
        print(f"[DISCONNECTED] {client_id} | Active clients: {count}")


def main():
    STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    if PORT == JSON_PORT:
        raise ValueError("PORT and JSON_PORT must be different")

    # Each protocol has its own greeting and framing. Both run at once.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as json_server, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as legacy_server, \
            selectors.DefaultSelector() as selector:
        for listener, address, handler in (
            (json_server, JSON_ADDR, handle_client),
            (legacy_server, ADDR, handle_legacy_client),
        ):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", address[1]))
            listener.listen(10)
            selector.register(listener, selectors.EVENT_READ, handler)

        print(f"[SERVER] Legacy OK@message protocol on {IP}:{PORT}")
        print(f"[SERVER] JSON file-sharing protocol on {IP}:{JSON_PORT}")
        print(f"[SERVER] Storage directory: {STORAGE_ROOT}")
        print("[ANALYSIS] Monitoring enabled")
        try:
            while True:
                for key, _ in selector.select(timeout=0.5):
                    conn, addr = key.fileobj.accept()
                    threading.Thread(
                        target=key.data, args=(conn, addr), daemon=True,
                    ).start()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
            analyzer.display_summary()


if __name__ == "__main__":
    main()
