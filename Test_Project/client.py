import hashlib
import json
import os
import socket
import time

import analysis

DEFAULT_PORT = 4500
PASSWORD_SALT = "CNT3004_FL26_SECURE_SALT"
CHUNK = 64 * 1024

sock = None
reader = None


def send(payload):
    sock.sendall((json.dumps(payload) + "\n").encode())


def receive():
    line = reader.readline()
    if not line:
        raise ConnectionError("Server closed the connection")
    return json.loads(line.decode())


def request(payload):
    start = time.time()
    send(payload)
    reply = receive()
    return reply, time.time() - start


def send_metric(metric):
    send(metric)
    receive()  # the server answers every METRIC


def timed(operation, payload):
    reply, elapsed = request(payload)
    status = "error" if reply["status"] == "ERROR" else "success"
    send_metric(analysis.make_response_metric(operation, elapsed, status))
    return reply


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def show_progress(done, total, start, base=0):
    speed = (done - base) / 1_000_000 / max(time.time() - start, 1e-6)
    print(f"\r  {done / total * 100 if total else 100:5.1f}%  {speed:7.2f} MB/s", end="", flush=True)


def connect(ip, port):
    global sock, reader
    sock = socket.create_connection((ip, port), timeout=10)
    sock.settimeout(None)
    reader = sock.makefile("rb")
    print(receive()["message"])  # snd init msg

    user = input("Username: ")
    password = input("Password: ")
    pw_hash = hashlib.sha256((PASSWORD_SALT + password).encode()).hexdigest()
    reply, _ = request({"command": "AUTH", "username": user, "password_hash": pw_hash})
    print(reply["message"])
    if reply["status"] != "SUCCESS":
        disconnect_socket()


def disconnect_socket():
    global sock, reader
    if sock:
        sock.close()
    sock = None
    reader = None


def upload(path, subfolder):
    if not os.path.isfile(path):
        print("Err: no file found locally")
        return
    name, size = os.path.basename(path), os.path.getsize(path)
    print("Calculating checksum...")
    payload = {"command": "UPLOAD", "filename": name, "subfolder": subfolder,
               "size": size, "overwrite": False, "sha256": sha256_file(path)}

    reply, response_time = request(payload)
    if reply["status"] == "EXISTS":  # server asks before overwriting
        if input(f"{reply['message']} Overwrite? (yes/no): ").strip().lower() != "yes":
            print("Upload cancelled")
            return
        payload["overwrite"] = True
        reply, response_time = request(payload)
    if reply["status"] != "READY":
        print("Err:", reply["message"])
        return

    sent, start = 0, time.time()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            sock.sendall(chunk)
            sent += len(chunk)
            show_progress(sent, size, start)
    result = receive()
    duration = time.time() - start
    ok = result["status"] == "SUCCESS"
    print("\n" + result["message"], f"| {sent / 1_000_000:.2f} MB in {duration:.2f} s "
                                    f"({sent / 1_000_000 / max(duration, 1e-6):.2f} MB/s)" if ok else "")

    send_metric(analysis.make_response_metric("upload", response_time))
    send_metric(analysis.make_transfer_metric("upload", name, sent, duration, "success" if ok else "error"))


def download(name, subfolder):
    # Download a file. If downloads/<name>.part exists from an interrupted
    # download, ask the server only for the bytes after it (resume)
    os.makedirs("downloads", exist_ok=True)
    dest = os.path.join("downloads", name)
    part = dest + ".part"
    offset = os.path.getsize(part) if os.path.exists(part) else 0
    reply = None

    for _ in range(5):  # the server may still be releasing the file (e.g. just uploaded or dropped)
        reply, response_time = request({"command": "DOWNLOAD", "filename": name,
                                        "subfolder": subfolder, "offset": offset})
        if reply["status"] == "ERROR" and "locked" in reply["message"]:
            time.sleep(0.5)
            continue
        break
    if reply["status"] != "READY":
        print("Error:", reply["message"])
        if "offset exceeds" in reply["message"]:  # stale partial file
            os.remove(part)
            print("Old partial file removed; Re-run download command")
        return

    h = hashlib.sha256()
    if offset:
        print(f"Resuming from byte {offset} ({offset / 1_000_000:.2f} MB already saved)")
        with open(part, "rb") as f:  # hash the part we already have
            for chunk in iter(lambda: f.read(CHUNK), b""):
                h.update(chunk)

    remaining, total = reply["sending_bytes"], reply["total_size"]
    got, start = 0, time.time()
    with open(part, "ab") as f:  # keep .part file if conn drops
        while got < remaining:
            data = reader.read(min(CHUNK, remaining - got))
            if not data:
                raise ConnectionError("Connection lost during download (partial file kept)")
            f.write(data)
            h.update(data)
            got += len(data)
            show_progress(offset + got, total, start, offset)
    duration = time.time() - start

    verified = h.hexdigest() == reply["sha256"]
    if verified:
        os.replace(part, dest)
    else:
        os.remove(part)
    print(f"\nSaved to {dest} | transferred {got / 1_000_000:.2f} MB in {duration:.2f} s "
          f"({got / 1_000_000 / max(duration, 1e-6):.2f} MB/s) | "
          f"SHA-256 {'verified' if verified else 'MISMATCH - partial file discarded, try again'}")

    send_metric(analysis.make_response_metric("download", response_time))
    send_metric(analysis.make_transfer_metric("download", name, got, duration,
                                              "success" if verified else "error"))


def list_dir(path):
    reply = timed("dir", {"command": "DIR", "path": path})
    if reply["status"] != "SUCCESS":
        print("Error:", reply["message"])
        return
    for e in reply["entries"] or [{"name": "(empty)", "type": "", "size_bytes": 0}]:
        size = "[DIR]" if e["type"] == "directory" else f"{e['size_bytes'] / 1_000_000:.2f} MB"
        print(f"  {size:>12}  {e['name']}")


def show_message(operation, payload):
    reply = timed(operation, payload)
    print(reply["message"] if reply["status"] == "SUCCESS" else "Error: " + reply["message"])


HELP_TEXT = """Commands:
  connect <ip> [port]            (default port 4450)
  upload <local file> [subfolder]
  download <filename> [subfolder]
  delete <filename> [subfolder]
  dir [path]
  subfolder create|delete <path>
  disconnect
  help | quit"""


def main():
    print(HELP_TEXT)
    while True:
        parts = input("input command:").strip().split()
        if not parts:
            continue
        cmd, args = parts[0].lower(), parts[1:]
        sub = args[1] if len(args) > 1 else ""

        try:
            if cmd == "help":
                print(HELP_TEXT)
            elif cmd == "quit":
                if sock:
                    send({"command": "DISCONNECT"})
                    disconnect_socket()
                break
            elif cmd == "connect" and args:
                if sock:
                    print("Already connected.")
                else:
                    connect(args[0], int(args[1]) if len(args) > 1 else DEFAULT_PORT)
            elif sock is None:
                print("Not connected. Use: connect <ip> [port]")
            elif cmd == "upload" and args:
                upload(args[0], sub)
            elif cmd == "download" and args:
                download(args[0], sub)
            elif cmd == "delete" and args:
                show_message("delete", {"command": "DELETE", "filename": args[0], "subfolder": sub})
            elif cmd == "dir":
                list_dir(args[0] if args else "")
            elif cmd == "subfolder" and len(args) == 2 and args[0] in ("create", "delete"):
                show_message("subfolder", {"command": "SUBFOLDER", "action": args[0], "path": args[1]})
            elif cmd == "disconnect":
                print(request({"command": "DISCONNECT"})[0]["message"])
                disconnect_socket()
            else:
                print("Invalid command; try help")
        except KeyboardInterrupt:
            disconnect_socket()
        except (ConnectionError, OSError) as e:
            print(f"\nConnection problem: {e}")
            disconnect_socket()
        except (ValueError, KeyError):
            print("Invalid input or unexpected reply from server.")


if __name__ == "__main__":
    main()
