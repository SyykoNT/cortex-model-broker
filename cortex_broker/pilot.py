"""Supervised network-none pilot transport, explicitly separate from setup mode."""
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import uuid

from .admin import peer_uid, protected_directory, strict_json
from .protocol import Refusal
from .worker import WorkerHandler, WorkerServer


class PilotReadiness:
    """Synchronous controller capture transaction, not a cached heartbeat file."""
    def __init__(self, capture, socket_path, runner_uid):
        self.capture, self.path, self.uid = capture, Path(socket_path), runner_uid

    def check(self, run_id=None):
        if not self.capture.healthy():
            return False
        try:
            for p in self.path.parents:
                s = p.lstat()
                if not stat.S_ISDIR(s.st_mode) or s.st_uid not in {0, self.uid} or s.st_mode & 0o022:
                    return False
            s = self.path.lstat()
            if not stat.S_ISSOCK(s.st_mode) or s.st_uid != self.uid or stat.S_IMODE(s.st_mode) != 0o660:
                return False
            nonce = uuid.uuid4().hex
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(3)
                conn.connect(str(self.path))
                if peer_uid(conn) != self.uid:
                    return False
                conn.sendall((json.dumps({'command': 'capture_check', 'run_id': run_id, 'nonce': nonce})+'\n').encode())
                conn.shutdown(socket.SHUT_WR)
                raw = bytearray()
                while True:
                    part = conn.recv(4097-len(raw))
                    if not part: break
                    raw.extend(part)
                    if len(raw)>4096: return False
            result = strict_json(raw)
            return result == {'ok': True, 'nonce': nonce, 'run_id': run_id, 'network': 'none',
                              'stdout': 'fsynced', 'events': 'fsynced', 'diff': 'fsynced'}
        except Exception:
            return False

    def worker_ready(self):
        return self.check()

    def snapshot(self):
        ok = self.worker_ready()
        return {'worker_inference': ok, 'capture_scope': 'supervised_network_none',
                'blockers': [] if ok else ['pilot_capture_unavailable']}


class PilotTransport:
    """Delegates every byte to the actual broker Transport; gates dispatch/delivery."""
    def __init__(self, transport, readiness):
        self.transport, self.readiness = transport, readiness
        self.keys, self.capture = transport.keys, transport.capture

    def responses(self, key, payload, emit):
        run = self.keys.run_for_key(key)
        if not self.keys.worker_key_active(key) or not self.readiness.check(run):
            raise Refusal('capture_unavailable')
        def guarded_emit(*args):
            if not self.readiness.check(run):
                raise Refusal('capture_unavailable')
            return emit(*args)
        return self.transport.responses(key, payload, guarded_emit)


class UnixWorkerServer(socketserver.UnixStreamServer):
    """Only this socket is mounted into network-none workers; never the admin socket."""
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        return connection, address

    handle_error = WorkerServer.handle_error
    start = WorkerServer.start
    request_queue_size = 8

    def __init__(self, path, group_gid, readiness, transport):
        self.path = Path(path)
        protected_directory(self.path.parent)
        if os.path.lexists(self.path):
            raise Refusal('worker_socket_exists')
        self.readiness, self.transport, self.thread = readiness, transport, None
        self.authority = '127.0.0.1:18743'
        self.identity = None
        # umask 0077 keeps the node private until its group and mode are set.
        super().__init__(str(self.path), WorkerHandler)
        os.chown(self.path, os.geteuid(), group_gid)
        os.chmod(self.path, 0o660)
        s = self.path.lstat()
        self.identity = s.st_dev, s.st_ino

    def close(self):
        WorkerServer.close(self)
        if self.identity:
            s = self.path.lstat()
            if (s.st_dev, s.st_ino) == self.identity:
                self.path.unlink()
