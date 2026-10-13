"""Real broker capture checks for fixed admin acceptance, never worker readiness."""
import os
from pathlib import Path
import secrets
import stat
import subprocess
import threading

from .admin import protected_directory
from .protocol import Refusal
from .traffic import Capture


class BrokerCapture(Capture):
    """Require a prepared protected directory and an actual functioning scanner.

    Each operation probes scanner detection and clean input, write/fsync/readback,
    directory fsync and path identity. No cached heartbeat or existence-only bit.
    The probe contains random nonsecret bytes, never a provider credential.
    """
    def __init__(self, directory, scanner):
        root = Path(directory)
        if not root.is_absolute() or '..' in root.parts:
            raise Refusal('capture_unavailable')
        protected_directory(root)
        s = root.lstat()
        if s.st_mode & 0o007:
            raise Refusal('capture_unavailable')
        self.identity = (s.st_dev, s.st_ino)
        self.probe_lock = threading.Lock()
        super().__init__(root, str(scanner), self.healthy)
        if not self.healthy():
            raise Refusal('capture_unavailable')

    def check_paths(self):
        protected_directory(self.root)
        s = self.root.lstat()
        if (s.st_dev, s.st_ino) != self.identity or s.st_mode & 0o007:
            raise Refusal('capture_unavailable')
        binary = Path(self.scanner)
        if not binary.is_absolute() or '..' in binary.parts:
            raise Refusal('capture_unavailable')
        for parent in binary.parents:
            s = parent.lstat()
            if (not stat.S_ISDIR(s.st_mode) or s.st_uid not in {0, os.geteuid()}
                    or s.st_mode & 0o022):
                raise Refusal('capture_unavailable')
        s = binary.lstat()
        if (not stat.S_ISREG(s.st_mode) or s.st_uid not in {0, os.geteuid()}
                or s.st_mode & 0o022 or not s.st_mode & 0o111):
            raise Refusal('capture_unavailable')

    def healthy(self):
        # A busy/failed probe is not permission to reuse yesterday's success.
        if not self.probe_lock.acquire(timeout=1):
            return False
        try:
            self.check_paths()
            # Exercise both exit codes. The canary is created only in memory;
            # scanner output is discarded, not written to an audit artifact.
            canary = ('gh' + 'p_' + secrets.token_hex(18)).encode()
            for body, expected in ((b'{"capture_probe":"clean"}', 0), (canary, 1)):
                result = subprocess.run([self.scanner, 'stdin', '--redact', '--no-banner',
                                         '--log-level', 'error'], input=body,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        timeout=5, cwd=self.root,
                                        env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root)})
                if result.returncode != expected:
                    return False
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                s = os.fstat(directory)
                if (s.st_dev, s.st_ino) != self.identity:
                    return False
                name = '.capture-probe-' + secrets.token_hex(12)
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_NONBLOCK, 0o640, dir_fd=directory)
                try:
                    s = os.fstat(fd)
                    if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid()
                            or s.st_nlink != 1 or s.st_mode & 0o027):
                        return False
                    body = ('broker-capture-probe:' + secrets.token_hex(16) + '\n').encode()
                    if os.pwrite(fd, body, 0) != len(body):
                        return False
                    os.ftruncate(fd, len(body))
                    os.fsync(fd)
                    os.fsync(directory)
                    if os.pread(fd, len(body) + 1, 0) != body:
                        return False
                finally:
                    os.close(fd)
                    os.unlink(name, dir_fd=directory)
                    os.fsync(directory)
            finally:
                os.close(directory)
            self.check_paths()
            return True
        except Exception:
            return False
        finally:
            self.probe_lock.release()

    def on_limit(self, run, details):
        # Admin acceptance has no worker orchestrator to notify. Preserve the
        # actual observation; never claim a global pause or a quota estimate.
        self.append(run, 'admin.usage_limit', details)
