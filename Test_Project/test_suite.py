# generated test suite

# use the following to run the tests locally/externally
# python test_suite.py                    # starts its own temporary server (safe, isolated)
# python test_suite.py --full-size        # also tests the required 25 MB / 1 GB / 2 GB files
# python test_suite.py --host 192.168.1.5 # test an already running server on another computer
# python test_suite.py TestDelete         # run only one group (any unittest argument works)

import argparse
import contextlib
import csv
import hashlib
import io
import itertools
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analysis  # noqa: E402
import client  # noqa: E402

MB = 1_000_000
USERS = {"student1": "NetPass2026", "student2": "CloudFileShare!", "admin": "AdminPass123!"}
CFG = {"host": "127.0.0.1", "port": 14450, "external": False, "full": False}
if os.environ.get("CNT_HOST"):  # e.g. CNT_HOST=192.168.1.5  CNT_PORT=4450
    CFG.update(host=os.environ["CNT_HOST"], external=True, port=int(os.environ.get("CNT_PORT", 4450)))
if os.environ.get("CNT_FULL_SIZE") == "1":
    CFG["full"] = True
WORK = SRC = SERVER_DIR = PROC = LOG = None
_counter = itertools.count(1)
_big_cache = {}


# ============================================================ module set-up
def setUpModule():
    global WORK, SRC, SERVER_DIR, PROC, LOG
    WORK = Path(tempfile.mkdtemp(prefix="cnt3004_test_"))
    SRC = WORK / "source_files"
    SRC.mkdir()
    os.chdir(WORK)  # the client saves to ./downloads

    if not CFG["external"]:
        SERVER_DIR = WORK / "server_side"
        SERVER_DIR.mkdir()
        text = (HERE / "server.py").read_text(encoding="utf-8")
        text = re.sub(r'(?m)^IP = .*$', 'IP = "127.0.0.1"', text)
        text = re.sub(r'(?m)^PORT = .*$', f'PORT = {CFG["port"] + 50}', text)
        text = re.sub(r'(?m)^JSON_PORT = .*$', f'JSON_PORT = {CFG["port"]}', text)
        (SERVER_DIR / "server.py").write_text(text, encoding="utf-8")
        shutil.copy(HERE / "analysis.py", SERVER_DIR / "analysis.py")
        LOG = open(SERVER_DIR / "server.log", "w", encoding="utf-8")
        env = dict(os.environ, PYTHONUTF8="1", PYTHONUNBUFFERED="1")  # avoid Windows cp1252 print crashes
        PROC = subprocess.Popen([sys.executable, "server.py"], cwd=SERVER_DIR, env=env,
                                stdout=LOG, stderr=subprocess.STDOUT)

    deadline = time.time() + 15
    while time.time() < deadline:
        if PROC and PROC.poll() is not None:
            break  # the temporary server crashed: stop waiting and show why
        try:
            socket.create_connection((CFG["host"], CFG["port"]), timeout=1).close()
            return
        except OSError:
            time.sleep(0.2)

    details = ""
    if PROC:
        crashed = PROC.poll() is not None
        if not crashed:
            PROC.terminate()
        LOG.close()
        details = ("\n--- temporary server " + (
            "CRASHED" if crashed else "is running but not listening on the expected port")
                   + " ---\n" + (SERVER_DIR / "server.log").read_text(encoding="utf-8", errors="replace")
                   + "\n(server.py was patched to use JSON_PORT=" + str(CFG["port"]) + ")")
    raise RuntimeError(f"Server not reachable at {CFG['host']}:{CFG['port']}{details}")


def tearDownModule():
    client.disconnect_socket()
    if PROC:
        PROC.terminate()
        PROC.wait(timeout=10)
    if LOG:
        LOG.close()
    os.chdir(HERE)
    shutil.rmtree(WORK, ignore_errors=True)


# ================================================================= helpers
def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_file(path, size):
    """Create a file of exactly `size` bytes of random data (fast for huge files)."""
    path = Path(path)
    block = os.urandom(min(size, MB))
    with open(path, "wb") as f:
        left = size
        while left > 0:
            f.write(block[:left])
            left -= len(block)
    return path


def big_file():
    """A 64 MB file, big enough that the server blocks while sending it."""
    if "big" not in _big_cache:
        _big_cache["big"] = make_file(SRC / "big64.bin", 64 * MB)
    return _big_cache["big"]


def unique(prefix="x"):
    return f"{prefix}{os.getpid()}_{next(_counter)}"


class Raw:
    """Minimal protocol client used to test the server independently of client.py."""

    def __init__(self, user="student1", timeout=120):
        self.sock = socket.create_connection((CFG["host"], CFG["port"]), timeout=timeout)
        self.reader = self.sock.makefile("rb")
        self.greeting = self.recv()
        if user:
            self.login(user)

    def send(self, payload):
        self.sock.sendall((json.dumps(payload) + "\n").encode())

    def recv(self):
        line = self.reader.readline()
        assert line, "server closed the connection"
        return json.loads(line)

    def cmd(self, payload):
        self.send(payload)
        return self.recv()

    def login(self, user, password=None):
        pw = USERS[user] if password is None else password
        digest = hashlib.sha256((client.PASSWORD_SALT + pw).encode()).hexdigest()
        return self.cmd({"command": "AUTH", "username": user, "password_hash": digest})

    def upload(self, path, sub="", name=None, overwrite=False, bad_hash=False):
        path = Path(path)
        reply = self.cmd({"command": "UPLOAD", "filename": name or path.name, "subfolder": sub,
                          "size": path.stat().st_size, "overwrite": overwrite,
                          "sha256": "0" * 64 if bad_hash else file_sha(path)})
        if reply["status"] != "READY":
            return reply
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                self.sock.sendall(chunk)
        final = self.recv()
        time.sleep(0.1)  # server.py sends SUCCESS slightly before it releases its file lock
        return final

    def download(self, name, dest, sub="", offset=0):
        reply = self.cmd({"command": "DOWNLOAD", "filename": name, "subfolder": sub, "offset": offset})
        if reply["status"] != "READY":
            return reply
        got = 0
        with open(dest, "wb") as f:
            while got < reply["sending_bytes"]:
                data = self.reader.read(min(65536, reply["sending_bytes"] - got))
                assert data, "connection lost"
                f.write(data)
                got += len(data)
        reply["received"] = got
        return reply

    def new_folder(self):
        name = unique("t")
        assert self.cmd({"command": "SUBFOLDER", "action": "create", "path": name})["status"] == "SUCCESS"
        return name

    def listing(self, path=""):
        reply = self.cmd({"command": "DIR", "path": path})
        assert reply["status"] == "SUCCESS", reply
        return {e["name"]: e for e in reply["entries"]}

    def close(self):
        try:
            self.reader.close()
            self.sock.close()
        except OSError:
            pass


def login(user="student1", password=None):
    """Log in through client.py's own connect(); returns the text it printed."""
    out = io.StringIO()
    with mock.patch("builtins.input", return_value=user), \
            mock.patch.object(client, "getpass", return_value=password or USERS.get(user, "bad")), \
            contextlib.redirect_stdout(out):
        client.connect(CFG["host"], CFG["port"])
    return out.getvalue()


def captured(fn, *args, answers=()):
    """Call a client.py function, return everything it printed."""
    out, it = io.StringIO(), iter(answers)
    with mock.patch("builtins.input", lambda p="": next(it)), contextlib.redirect_stdout(out):
        fn(*args)
    return out.getvalue()


class ServerTestCase(unittest.TestCase):
    """Base: one authenticated raw connection and a fresh, empty server subfolder."""

    def setUp(self):
        self.r = Raw("student1")
        self.addCleanup(self.r.close)
        self.addCleanup(client.disconnect_socket)
        self.sub = self.r.new_folder()


# ======================================================== 1. Authentication
class TestAuthentication(unittest.TestCase):
    def test_server_greets_on_connect(self):
        r = Raw(None)
        self.addCleanup(r.close)
        self.assertEqual(r.greeting["status"], "OK")

    def test_valid_login_for_every_demo_account(self):
        for user in USERS:
            r = Raw(None)
            self.addCleanup(r.close)
            self.assertEqual(r.login(user)["status"], "SUCCESS", user)

    def test_wrong_password_rejected(self):
        r = Raw(None)
        self.addCleanup(r.close)
        reply = r.login("student1", "not-the-password")
        self.assertEqual(reply["status"], "ERROR")

    def test_unknown_user_rejected(self):
        r = Raw(None)
        self.addCleanup(r.close)
        self.assertEqual(r.cmd({"command": "AUTH", "username": "nobody", "password_hash": "0" * 64})["status"], "ERROR")

    def test_commands_refused_before_login(self):
        r = Raw(None)
        self.addCleanup(r.close)
        for payload in ({"command": "DIR"}, {"command": "DELETE", "filename": "a.txt"},
                        {"command": "UPLOAD", "filename": "a.txt", "size": 1},
                        {"command": "DOWNLOAD", "filename": "a.txt"},
                        {"command": "SUBFOLDER", "action": "create", "path": "x"}):
            reply = r.cmd(payload)
            self.assertEqual(reply["status"], "ERROR", payload)
            self.assertIn("Authentication", reply["message"])

    def test_password_never_sent_in_clear_text(self):
        sent = []
        original = client.send
        with mock.patch.object(client, "send", lambda p: (sent.append(json.dumps(p)), original(p))):
            login("student1")
        client.disconnect_socket()
        wire = "".join(sent)
        self.assertNotIn(USERS["student1"], wire)
        self.assertIn("password_hash", wire)

    def test_client_reports_failed_login_and_stays_disconnected(self):
        text = login("student1", "wrong")
        self.assertIn("Invalid username or password", text)
        self.assertIsNone(client.sock)

    def test_client_login_success(self):
        self.assertIn("Welcome, student1", login("student1"))
        self.assertIsNotNone(client.sock)
        client.disconnect_socket()


# ================================================================ 2. Upload
class TestUpload(ServerTestCase):
    def test_logical_names_identify_file_type(self):
        for ext, prefix in ((".txt", "TS"), (".wav", "AS"), (".mp3", "AS"), (".mp4", "VS")):
            reply = self.r.upload(make_file(SRC / f"a{ext}", 100_000), self.sub)
            self.assertEqual(reply["status"], "SUCCESS", reply)
            self.assertRegex(reply["assigned_name"], rf"^{prefix}\d{{3}}\{ext}$")

    def test_duplicate_logical_names_are_avoided(self):
        names = {self.r.upload(make_file(SRC / f"doc{i}.txt", 50_000), self.sub)["assigned_name"] for i in range(5)}
        self.assertEqual(len(names), 5)

    def test_upload_reports_size_hash_and_rate(self):
        path = make_file(SRC / "stats.txt", 3 * MB)
        reply = self.r.upload(path, self.sub)
        self.assertEqual(reply["size_bytes"], 3 * MB)
        self.assertEqual(reply["sha256"], file_sha(path))
        self.assertGreater(reply["transfer_rate_mbs"], 0)

    def test_existing_file_asks_before_overwriting(self):
        first = make_file(SRC / "same.txt", 200_000)
        self.assertEqual(self.r.upload(first, self.sub)["status"], "SUCCESS")
        original_hash = file_sha(first)
        second = make_file(SRC / "same.txt", 200_000)  # same name, new content
        reply = self.r.upload(second, self.sub)
        self.assertEqual(reply["status"], "EXISTS")
        self.r.download("same.txt", SRC / "check.txt", self.sub)
        self.assertEqual(file_sha(SRC / "check.txt"), original_hash)  # untouched

    def test_confirmed_overwrite_replaces_file(self):
        make_file(SRC / "ow.txt", 200_000)
        first = self.r.upload(SRC / "ow.txt", self.sub)
        new = make_file(SRC / "ow.txt", 300_000)
        reply = self.r.upload(new, self.sub, overwrite=True)
        self.assertEqual(reply["status"], "SUCCESS")
        self.assertEqual(reply["assigned_name"], first["assigned_name"])
        self.r.download("ow.txt", SRC / "check.txt", self.sub)
        self.assertEqual(file_sha(SRC / "check.txt"), file_sha(new))

    def test_corrupted_upload_is_rejected_and_not_stored(self):
        reply = self.r.upload(make_file(SRC / "bad.txt", 100_000), self.sub, bad_hash=True)
        self.assertEqual(reply["status"], "ERROR")
        self.assertIn("mismatch", reply["message"])
        self.assertEqual(self.r.listing(self.sub), {})

    def test_file_lands_in_requested_subfolder_only(self):
        reply = self.r.upload(make_file(SRC / "where.txt", 10_000), self.sub)
        self.assertIn(reply["assigned_name"], self.r.listing(self.sub))
        root = self.r.listing("").get(reply["assigned_name"])  # another test may own a root file with this name
        self.assertTrue(root is None or root["size_bytes"] != 10_000)

    def test_empty_file(self):
        reply = self.r.upload(make_file(SRC / "empty.txt", 0), self.sub)
        self.assertEqual(reply["status"], "SUCCESS")
        self.assertEqual(reply["size_bytes"], 0)

    @unittest.skipUnless(CFG["full"] or "--full-size" in sys.argv, "needs --full-size (or CNT_FULL_SIZE=1)")
    def test_required_file_sizes(self):
        """25 MB text, 1 GB audio, 2 GB video: upload then download and compare."""
        r = Raw("student1", timeout=900)
        self.addCleanup(r.close)
        for name, size in (("big.txt", 25 * MB), ("big.wav", 1000 * MB), ("big.mp4", 2000 * MB)):
            path = make_file(SRC / name, size)
            reply = r.upload(path, self.sub)
            self.assertEqual(reply["status"], "SUCCESS", f"{name}: {reply}")
            r.download(name, SRC / f"back_{name}", self.sub)
            self.assertEqual(file_sha(SRC / f"back_{name}"), file_sha(path), name)
            r.cmd({"command": "DELETE", "filename": name, "subfolder": self.sub})
            os.remove(SRC / f"back_{name}")
            os.remove(path)


# ============================================================== 3. Download
class TestDownload(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.original = make_file(SRC / "report.txt", 3 * MB)
        self.assigned = self.r.upload(self.original, self.sub)["assigned_name"]

    def test_download_by_original_name_is_identical(self):
        reply = self.r.download("report.txt", SRC / "d1.txt", self.sub)
        self.assertEqual(reply["status"], "READY")
        self.assertEqual(file_sha(SRC / "d1.txt"), file_sha(self.original))

    def test_download_by_logical_name(self):
        self.r.download(self.assigned, SRC / "d2.txt", self.sub)
        self.assertEqual(file_sha(SRC / "d2.txt"), file_sha(self.original))

    def test_server_sends_matching_sha256(self):
        reply = self.r.download("report.txt", SRC / "d3.txt", self.sub)
        self.assertEqual(reply["sha256"], file_sha(self.original))
        self.assertEqual(reply["total_size"], 3 * MB)

    def test_missing_file_gives_error(self):
        reply = self.r.download("ghost.txt", SRC / "ghost.txt", self.sub)
        self.assertEqual(reply["status"], "ERROR")
        self.assertIn("does not exist", reply["message"])

    def test_offset_sends_only_remaining_bytes(self):
        reply = self.r.download("report.txt", SRC / "tail.bin", self.sub, offset=1_000_000)
        self.assertEqual(reply["received"], 2 * MB)
        self.assertEqual((SRC / "tail.bin").read_bytes(), self.original.read_bytes()[1_000_000:])

    def test_offset_beyond_file_is_rejected(self):
        reply = self.r.download("report.txt", SRC / "x.bin", self.sub, offset=10 * MB)
        self.assertEqual(reply["status"], "ERROR")


# =============================================================== 4. Delete
class TestDelete(ServerTestCase):
    def test_delete_existing_file(self):
        reply = self.r.upload(make_file(SRC / "del.txt", 10_000), self.sub)
        res = self.r.cmd({"command": "DELETE", "filename": "del.txt", "subfolder": self.sub})
        self.assertEqual(res["status"], "SUCCESS")
        self.assertNotIn(reply["assigned_name"], self.r.listing(self.sub))
        self.assertEqual(self.r.download("del.txt", SRC / "n", self.sub)["status"], "ERROR")

    def test_delete_missing_file_gives_error(self):
        res = self.r.cmd({"command": "DELETE", "filename": "nope.txt", "subfolder": self.sub})
        self.assertEqual(res["status"], "ERROR")
        self.assertIn("does not exist", res["message"])

    def test_delete_refused_while_file_is_being_downloaded(self):
        self.assertEqual(self.r.upload(big_file(), self.sub)["status"], "SUCCESS")
        slow = Raw("student2")
        self.addCleanup(slow.close)
        slow.send({"command": "DOWNLOAD", "filename": "big64.bin", "subfolder": self.sub, "offset": 0})
        ready = slow.recv()
        self.assertEqual(ready["status"], "READY", ready)
        slow.reader.read(1000)  # read almost nothing: the server stays busy sending
        time.sleep(0.5)
        res = self.r.cmd({"command": "DELETE", "filename": "big64.bin", "subfolder": self.sub})
        self.assertEqual(res["status"], "ERROR")
        self.assertIn("being processed", res["message"])
        slow.close()  # lock is released once the slow client is gone
        deadline = time.time() + 15
        while time.time() < deadline:
            res = self.r.cmd({"command": "DELETE", "filename": "big64.bin", "subfolder": self.sub})
            if res["status"] == "SUCCESS":
                break
            time.sleep(0.5)
        self.assertEqual(res["status"], "SUCCESS")


# ============================================ 5. Dir and subfolders
class TestDirAndSubfolders(ServerTestCase):
    def test_dir_lists_files_with_sizes_and_subfolders(self):
        self.r.cmd({"command": "SUBFOLDER", "action": "create", "path": f"{self.sub}/inner"})
        name = self.r.upload(make_file(SRC / "listed.txt", 123_456), self.sub)["assigned_name"]
        entries = self.r.listing(self.sub)
        self.assertEqual(entries[name]["type"], "file")
        self.assertEqual(entries[name]["size_bytes"], 123_456)
        self.assertEqual(entries["inner"]["type"], "directory")

    def test_empty_folder_lists_nothing(self):
        self.assertEqual(self.r.listing(self.sub), {})

    def test_dir_of_missing_folder_gives_error(self):
        self.assertEqual(self.r.cmd({"command": "DIR", "path": "no_such_folder"})["status"], "ERROR")

    def test_create_and_delete_subfolder(self):
        path = f"{self.sub}/made"
        self.assertEqual(self.r.cmd({"command": "SUBFOLDER", "action": "create", "path": path})["status"], "SUCCESS")
        self.assertIn("made", self.r.listing(self.sub))
        self.assertEqual(self.r.cmd({"command": "SUBFOLDER", "action": "delete", "path": path})["status"], "SUCCESS")
        self.assertNotIn("made", self.r.listing(self.sub))

    def test_nested_subfolders(self):
        res = self.r.cmd({"command": "SUBFOLDER", "action": "create", "path": f"{self.sub}/a/b/c"})
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIn("c", self.r.listing(f"{self.sub}/a/b"))

    def test_create_existing_subfolder_gives_error(self):
        self.assertEqual(self.r.cmd({"command": "SUBFOLDER", "action": "create", "path": self.sub})["status"], "ERROR")

    def test_delete_missing_subfolder_gives_error(self):
        res = self.r.cmd({"command": "SUBFOLDER", "action": "delete", "path": f"{self.sub}/ghost"})
        self.assertEqual(res["status"], "ERROR")

    def test_delete_non_empty_subfolder_refused(self):
        self.r.upload(make_file(SRC / "keep.txt", 1000), self.sub)
        self.assertEqual(self.r.cmd({"command": "SUBFOLDER", "action": "delete", "path": self.sub})["status"], "ERROR")

    def test_storage_root_cannot_be_removed(self):
        self.assertEqual(self.r.cmd({"command": "SUBFOLDER", "action": "delete", "path": ""})["status"], "ERROR")

    def test_invalid_subfolder_action(self):
        self.assertEqual(self.r.cmd({"command": "SUBFOLDER", "action": "rename", "path": "x"})["status"], "ERROR")


# ============================================================== 6. Security
class TestSecurity(ServerTestCase):
    BAD_PATHS = ["../escape", "/etc/escape", "..\\escape", "a/../../escape", "C:/escape"]

    def test_path_traversal_blocked_for_subfolders(self):
        for bad in self.BAD_PATHS:
            for action in ("create", "delete"):
                res = self.r.cmd({"command": "SUBFOLDER", "action": action, "path": bad})
                self.assertEqual(res["status"], "ERROR", f"{action} {bad}")
        if SERVER_DIR:
            self.assertFalse((SERVER_DIR / "escape").exists())

    def test_path_traversal_blocked_for_dir(self):
        for bad in self.BAD_PATHS:
            self.assertEqual(self.r.cmd({"command": "DIR", "path": bad})["status"], "ERROR", bad)

    def test_filenames_must_not_contain_paths(self):
        for bad in ("../x.txt", "a/b.txt", "..\\x.txt", ".."):
            up = self.r.cmd(
                {"command": "UPLOAD", "filename": bad, "subfolder": self.sub, "size": 1, "overwrite": False})
            dl = self.r.cmd({"command": "DOWNLOAD", "filename": bad, "subfolder": self.sub})
            de = self.r.cmd({"command": "DELETE", "filename": bad, "subfolder": self.sub})
            for res in (up, dl, de):
                self.assertEqual(res["status"], "ERROR", bad)

    def test_upload_and_download_blocked_outside_storage(self):
        for bad in self.BAD_PATHS:
            up = self.r.cmd({"command": "UPLOAD", "filename": "x.txt", "subfolder": bad, "size": 1, "overwrite": False})
            dl = self.r.cmd({"command": "DOWNLOAD", "filename": "x.txt", "subfolder": bad})
            self.assertEqual(up["status"], "ERROR", bad)
            self.assertEqual(dl["status"], "ERROR", bad)

    def test_unknown_command_gives_error_not_crash(self):
        self.assertEqual(self.r.cmd({"command": "FORMAT_DISK"})["status"], "ERROR")
        self.assertEqual(self.r.listing(self.sub), {})  # connection still usable

    def test_invalid_upload_parameters_rejected(self):
        for size in (-5, "10", 1.5):
            res = self.r.cmd({"command": "UPLOAD", "filename": "s.txt", "subfolder": self.sub, "size": size})
            self.assertEqual(res["status"], "ERROR", size)


# ============================================================ 7. Concurrency
class TestConcurrency(ServerTestCase):
    def test_two_clients_transfer_at_the_same_time(self):
        results, barrier = {}, threading.Barrier(2)

        def worker(user, tag):
            try:
                r = Raw(user)
                src = make_file(SRC / f"{tag}.txt", 20 * MB)
                barrier.wait(timeout=30)
                up = r.upload(src, self.sub)
                dst = SRC / f"{tag}_back.txt"
                r.download(f"{tag}.txt", dst, self.sub)
                results[tag] = (up, file_sha(src) == file_sha(dst))
                r.close()
            except Exception as error:  # report in the main thread
                results[tag] = error

        threads = [threading.Thread(target=worker, args=a) for a in (("student1", "c1"), ("student2", "c2"))]
        [t.start() for t in threads]
        [t.join(timeout=120) for t in threads]
        for tag in ("c1", "c2"):
            self.assertNotIsInstance(results.get(tag), Exception, results.get(tag))
            up, same = results[tag]
            self.assertEqual(up["status"], "SUCCESS")
            self.assertTrue(same, f"{tag}: downloaded file differs")
        self.assertNotEqual(results["c1"][0]["assigned_name"], results["c2"][0]["assigned_name"])

    def test_many_clients_connected_together(self):
        clients = [Raw(user) for user in ("student1", "student2", "admin", "student1", "student2")]
        for c in clients:
            self.addCleanup(c.close)
        replies = []
        threads = [threading.Thread(target=lambda c=c: replies.append(c.cmd({"command": "DIR", "path": self.sub})))
                   for c in clients]
        [t.start() for t in threads]
        [t.join(timeout=30) for t in threads]
        self.assertEqual(len(replies), 5)
        self.assertTrue(all(r["status"] == "SUCCESS" for r in replies))

    def test_simultaneous_uploads_get_unique_names(self):
        names, lock = [], threading.Lock()

        def worker(i):
            r = Raw("student1")
            res = r.upload(make_file(SRC / f"par{i}.txt", 2 * MB), self.sub)
            with lock:
                names.append(res["assigned_name"])
            r.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        [t.start() for t in threads]
        [t.join(timeout=60) for t in threads]
        self.assertEqual(len(names), 6)
        self.assertEqual(len(set(names)), 6)


# ============================================================== 8. Analysis
@unittest.skipIf(CFG["external"] or "--host" in sys.argv, "needs access to the server's files")
class TestAnalysis(unittest.TestCase):
    def rows(self):
        with open(SERVER_DIR / "network_stats.csv", newline="") as f:
            return list(csv.DictReader(f))

    def test_statistics_file_has_expected_columns(self):
        with open(SERVER_DIR / "network_stats.csv", newline="") as f:
            header = next(csv.reader(f))
        self.assertEqual(header, ["timestamp", "source", "client_id", "operation", "filename", "file_size_mb",
                                  "transfer_time_sec", "transfer_rate_mbps", "response_time_ms", "status"])

    def test_upload_download_and_response_times_recorded_from_both_sides(self):
        name = f"{unique('an')}.txt"
        make_file(SRC / name, 5 * MB)
        login("student1")
        captured(client.upload, str(SRC / name), "")
        captured(client.download, name, "")
        captured(client.list_dir, "")
        captured(client.show_message, "delete", {"command": "DELETE", "filename": name, "subfolder": ""})
        client.disconnect_socket()

        rows = self.rows()
        for source in ("server", "client"):
            for op in ("upload", "download"):
                hits = [r for r in rows if r["source"] == source and r["operation"] == op and r["file_size_mb"]]
                self.assertTrue(hits, f"no {source} {op} transfer row")
                self.assertGreater(float(hits[-1]["transfer_rate_mbps"]), 0)
                self.assertGreater(float(hits[-1]["transfer_time_sec"]), 0)
                self.assertAlmostEqual(float(hits[-1]["file_size_mb"]), 5.0, places=1)
            self.assertTrue([r for r in rows if r["source"] == source and r["operation"] == "dir"
                             and r["response_time_ms"]], f"no {source} response time for dir")

    def test_statistics_module_calculates_rate_and_response(self):
        a = analysis.NetworkAnalyzer(str(WORK / "unit_stats.csv"))
        row = a.record_transfer("client", "c1", "upload", "f.txt", 10_000_000, 2.0)
        self.assertEqual(row["file_size_mb"], 10.0)
        self.assertEqual(row["transfer_rate_mbps"], 5.0)
        self.assertEqual(a.record_response("server", "c1", "dir", 0.25)["response_time_ms"], 250.0)
        self.assertEqual(len(a.get_statistics()), 2)
        with self.assertRaises(ValueError):
            a.record_transfer("client", "c1", "copy", "f", 1, 1)

    def test_server_rejects_invalid_metric(self):
        r = Raw("student1")
        self.addCleanup(r.close)
        bad = {"command": "METRIC", "metric_type": "bogus", "operation": "upload", "status": "success"}
        self.assertEqual(r.cmd(bad)["status"], "ERROR")
        neg = analysis.make_transfer_metric("upload", "f", -5, 1.0)
        self.assertEqual(r.cmd(neg)["status"], "ERROR")


# ============================================================ 9. Client CLI
class TestClientCLI(unittest.TestCase):
    def run_cli(self, *inputs):
        """Run client.main() with scripted keyboard input; return what it printed."""
        it, out = iter(inputs), io.StringIO()

        def fake_input(prompt=""):
            print(prompt)
            try:
                return next(it)
            except StopIteration:
                raise EOFError

        with mock.patch("builtins.input", fake_input), \
                mock.patch.object(client, "getpass", return_value=USERS["student1"]), \
                contextlib.redirect_stdout(out):
            try:
                client.main()
            except EOFError:
                pass
        client.disconnect_socket()
        return out.getvalue()

    def connect(self):
        return f"connect {CFG['host']} {CFG['port']}"

    def test_full_session_of_every_command(self):
        sub, name = unique("cli"), f"{unique('f')}.txt"
        src = make_file(SRC / name, 2 * MB)
        out = self.run_cli(
            self.connect(), "student1",
            f"subfolder create {sub}",
            f"upload {src} {sub}",
            f"dir {sub}",
            f"download {name} {sub}",
            f"delete {name} {sub}",
            f"dir {sub}",
            f"subfolder delete {sub}",
            "disconnect", "quit")
        self.assertIn("Welcome, student1", out)
        self.assertIn(f"Created directory '{sub}'", out)
        self.assertIn("Uploaded", out)
        self.assertIn("2.00 MB", out)  # dir listing shows the size
        self.assertIn("SHA-256 verified", out)
        self.assertIn("Deleted", out)
        self.assertIn("(empty)", out)  # dir after delete
        self.assertIn(f"Deleted directory '{sub}'", out)
        self.assertIn("Logged out", out)
        self.assertEqual(file_sha(WORK / "downloads" / name), file_sha(src))

    def test_commands_need_a_connection(self):
        out = self.run_cli("dir", "upload x.txt", "download x.txt", "quit")
        self.assertEqual(out.count("Not connected"), 3)

    def test_unknown_and_incomplete_commands(self):
        out = self.run_cli(self.connect(), "student1", "fly", "upload", "help", "quit")
        self.assertEqual(out.count("Invalid command"), 2)  # unknown + missing argument
        self.assertGreaterEqual(out.count("Commands:"), 2)  # startup text + help

    def test_missing_local_file(self):
        out = self.run_cli(self.connect(), "student1", "upload /no/such/file.txt", "quit")
        self.assertIn("local file not found", out)

    def test_download_of_missing_file_shows_server_error(self):
        out = self.run_cli(self.connect(), "student1", "download ghost_file.txt", "quit")
        self.assertIn("does not exist", out)

    def test_overwrite_prompt_yes_and_no(self):
        sub, name = unique("ow"), f"{unique('o')}.txt"
        src = make_file(SRC / name, 100_000)
        out = self.run_cli(self.connect(), "student1", f"subfolder create {sub}",
                           f"upload {src} {sub}",
                           f"upload {src} {sub}", "no",
                           f"upload {src} {sub}", "yes", "quit")
        self.assertIn("already exists", out)
        self.assertIn("Upload cancelled", out)
        self.assertEqual(out.count("Uploaded"), 2)  # first upload + confirmed overwrite

    def test_wrong_password_in_cli(self):
        it, out = iter([self.connect(), "student1", "dir", "quit"]), io.StringIO()
        with mock.patch("builtins.input", lambda p="": next(it)), \
                mock.patch.object(client, "getpass", return_value="wrong"), \
                contextlib.redirect_stdout(out):
            client.main()
        self.assertIn("Invalid username or password", out.getvalue())
        self.assertIn("Not connected", out.getvalue())

    def test_connection_failure_is_reported_not_crashed(self):
        out = self.run_cli("connect 127.0.0.1 1", "quit")
        self.assertIn("Connection problem", out)


# ====================================================== 10. Bonus: resume
class TestBonusResume(unittest.TestCase):
    TOTAL = 48 * MB
    CUT = 16 * MB

    def setUp(self):
        self.r = Raw("student1")
        self.addCleanup(self.r.close)
        self.addCleanup(client.disconnect_socket)
        self.sub = self.r.new_folder()
        self.name = f"{unique('resume')}.bin"
        self.src = make_file(SRC / self.name, self.TOTAL)
        self.assertEqual(self.r.upload(self.src, self.sub)["status"], "SUCCESS")
        self.part = WORK / "downloads" / f"{self.name}.part"
        self.final = WORK / "downloads" / self.name

    def interrupt_download(self):
        """Start a download and drop the connection once CUT bytes have arrived."""

        def cutter(done, total, start, base=0):
            if done >= self.CUT:
                client.sock.close()
                raise ConnectionError("simulated network drop")

        login("student1")
        with mock.patch.object(client, "show_progress", cutter), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ConnectionError):
                client.download(self.name, self.sub)
        client.disconnect_socket()

    def resume_download(self):
        """Reconnect and repeat the download; returns (printed text, metrics sent)."""
        metrics, original = [], client.send_metric
        for _ in range(20):  # server may need a moment to release the file after the drop
            login("student1")
            with mock.patch.object(client, "send_metric", lambda m: (metrics.append(m), original(m))):
                out = captured(client.download, self.name, self.sub)
            client.disconnect_socket()
            if "locked" not in out:
                return out, metrics
            time.sleep(0.5)
        self.fail("file stayed locked after the connection was dropped")

    def test_interrupted_download_keeps_partial_file(self):
        self.interrupt_download()
        self.assertTrue(self.part.exists(), "partial file was not preserved")
        size = self.part.stat().st_size
        self.assertGreaterEqual(size, self.CUT)
        self.assertLess(size, self.TOTAL)
        self.assertFalse(self.final.exists())
        self.assertEqual(self.part.read_bytes(), self.src.read_bytes()[:size])  # correct prefix

    def test_resume_transfers_only_remaining_bytes_and_verifies(self):
        self.interrupt_download()
        partial = self.part.stat().st_size
        out, metrics = self.resume_download()
        self.assertIn("Resuming from byte", out)
        self.assertIn("SHA-256 verified", out)
        self.assertTrue(self.final.exists())
        self.assertFalse(self.part.exists())
        self.assertEqual(file_sha(self.final), file_sha(self.src))
        transfer = [m for m in metrics if m["metric_type"] == "transfer"][0]
        self.assertEqual(transfer["bytes_transferred"], self.TOTAL - partial)  # only the rest

    def test_corrupted_partial_file_is_detected_and_discarded(self):
        self.part.parent.mkdir(exist_ok=True)
        self.part.write_bytes(os.urandom(MB))  # wrong bytes, not a prefix of the file
        login("student1")
        out = captured(client.download, self.name, self.sub)
        client.disconnect_socket()
        self.assertIn("MISMATCH", out)
        self.assertFalse(self.part.exists())
        self.assertFalse(self.final.exists())
        login("student1")  # a fresh attempt now works
        out = captured(client.download, self.name, self.sub)
        client.disconnect_socket()
        self.assertIn("SHA-256 verified", out)
        self.assertEqual(file_sha(self.final), file_sha(self.src))

    def test_partial_larger_than_file_is_removed(self):
        self.part.parent.mkdir(exist_ok=True)
        self.part.write_bytes(b"x" * (self.TOTAL + 10))
        login("student1")
        out = captured(client.download, self.name, self.sub)
        client.disconnect_socket()
        self.assertIn("offset exceeds", out)
        self.assertFalse(self.part.exists())

    def test_download_without_partial_is_a_normal_download(self):
        login("student1")
        out = captured(client.download, self.name, self.sub)
        client.disconnect_socket()
        self.assertNotIn("Resuming", out)
        self.assertEqual(file_sha(self.final), file_sha(self.src))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--full-size", action="store_true")
    args, rest = parser.parse_known_args()
    if args.host:
        CFG.update(host=args.host, external=True, port=4450)
    if args.port:
        CFG["port"] = args.port
    CFG["full"] = args.full_size
    sys.argv = [sys.argv[0]] + rest
    unittest.main(verbosity=2)
