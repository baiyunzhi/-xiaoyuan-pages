"""Acquire encrypted MNQ packets and append only the dedicated Git cache branch."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from urllib.request import Request, urlopen

import packet

ACK_URL = 'https://hedong-xiaoyuan.top/markets/collectors/mnq-ack.json'
ACK_SCHEMA = 'xiaoyuan.mnq.delivery-ack.v1'
REFS = {'refs/heads/main': 'mnq-source-cache',
        'refs/heads/ops/always-on-collection-20261124': 'mnq-source-rc'}
FILES = {'manifest.json', 'packet.cms'}
MANIFEST_KEYS = {'schema', 'captured_at', 'ciphertext_sha256', 'ciphertext_bytes'}
SHA = re.compile(r'[0-9a-f]{64}\Z')
OID = re.compile(r'[0-9a-f]{40}\Z')
SHANGHAI = timezone(timedelta(hours=8), 'Asia/Shanghai')


def manifest(raw):
    if not 0 < len(raw) <= 4096:
        raise ValueError('manifest size invalid')
    body = packet.loads(raw)
    if (not isinstance(body, dict) or set(body) != MANIFEST_KEYS
            or body['schema'] != packet.CMS_SCHEMA
            or not isinstance(body['ciphertext_sha256'], str)
            or not SHA.fullmatch(body['ciphertext_sha256'])
            or type(body['ciphertext_bytes']) is not int
            or not 0 < body['ciphertext_bytes'] <= packet.MAX_CIPHER):
        raise ValueError('manifest schema invalid')
    packet.utc(body['captured_at'])
    return body


def due_batch(now):
    local = now.astimezone(SHANGHAI)
    due = local.replace(hour=15, minute=30, second=0, microsecond=0)
    if local < due:
        due -= timedelta(days=1)
    return due.astimezone(timezone.utc)


def accepted(cached, raw, now):
    """Missing/malformed public ACK means collect again, never infer delivery."""
    try:
        if cached is None or not 0 < len(raw) <= 4096:
            return False
        ack = packet.loads(raw)
        if (not isinstance(ack, dict)
                or set(ack) != {'schema', 'status', 'captured_at', 'ciphertext_sha256', 'accepted_at'}
                or ack['schema'] != ACK_SCHEMA or ack['status'] != 'accepted'
                or ack['captured_at'] != cached['captured_at']
                or ack['ciphertext_sha256'] != cached['ciphertext_sha256']):
            return False
        capture = packet.utc(cached['captured_at'])
        return due_batch(now) <= capture <= packet.utc(ack['accepted_at']) <= now
    except (ValueError, TypeError, KeyError):
        return False


def fetch_ack():
    try:
        request = Request(ACK_URL, headers={'User-Agent': 'xiaoyuan-mnq-source/1'})
        with urlopen(request, timeout=15) as response:
            if response.geturl() != ACK_URL or response.status != 200:
                return b''
            return response.read(4097)
    except Exception:
        return b''


class Cache:
    def __init__(self, repo, branch):
        if branch not in REFS.values():
            raise ValueError('cache branch not allowed')
        self.repo = Path(repo).resolve()
        self.ref = 'refs/heads/' + branch
        self.env = os.environ.copy()
        for name in ('GIT_INDEX_FILE', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR'):
            self.env.pop(name, None)
        self.env.update(GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0')

    def git(self, *args, data=None, env=None, check=True):
        result = subprocess.run(['git', '-C', str(self.repo), *args], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env or self.env, timeout=120, check=False)
        if check and result.returncode:
            # Checkout authentication headers and remote URLs must not enter logs.
            raise RuntimeError('Git operation failed: ' + args[0])
        return result

    def read(self):
        lookup = self.git('ls-remote', '--exit-code', '--heads', 'origin', self.ref, check=False)
        if lookup.returncode == 2 and not lookup.stdout:
            return None, None
        if lookup.returncode:
            raise RuntimeError('cache reference lookup failed')
        fields = lookup.stdout.decode('ascii').strip().split()
        if len(fields) != 2 or not OID.fullmatch(fields[0]) or fields[1] != self.ref:
            raise ValueError('cache reference invalid')
        head = fields[0]
        self.git('fetch', '--no-tags', '--no-write-fetch-head', 'origin', self.ref)
        tree = self.git('ls-tree', '-z', head).stdout.split(b'\0')
        entries = [item.split(b'\t', 1) for item in tree if item]
        if (len(entries) != 2 or {item[1].decode('ascii') for item in entries} != FILES
                or any(not item[0].startswith(b'100644 blob ') for item in entries)):
            raise ValueError('cache tree must contain only the two ciphertext files')
        size = int(self.git('cat-file', '-s', head + ':manifest.json').stdout)
        if not 0 < size <= 4096:
            raise ValueError('cached manifest oversized')
        body = manifest(self.git('show', head + ':manifest.json').stdout)
        if int(self.git('cat-file', '-s', head + ':packet.cms').stdout) != body['ciphertext_bytes']:
            raise ValueError('cached ciphertext size mismatch')
        encrypted = self.git('show', head + ':packet.cms').stdout
        if hashlib.sha256(encrypted).hexdigest() != body['ciphertext_sha256']:
            raise ValueError('cached ciphertext hash mismatch')
        return head, body

    def checkpoint(self):
        index = Path(os.fsdecode(self.git('rev-parse', '--git-path', 'index').stdout).strip())
        if not index.is_absolute():
            index = self.repo / index
        return self.git('rev-parse', 'HEAD').stdout, index, index.read_bytes() if index.exists() else None

    def publish(self, output, now):
        output = Path(output)
        if {item.name for item in output.iterdir()} != FILES or any(
                item.is_symlink() or not item.is_file() for item in output.iterdir()):
            raise ValueError('output must contain only two regular ciphertext files')
        body = manifest((output / 'manifest.json').read_bytes())
        encrypted = (output / 'packet.cms').read_bytes()
        if (len(encrypted) != body['ciphertext_bytes']
                or hashlib.sha256(encrypted).hexdigest() != body['ciphertext_sha256']):
            raise ValueError('local ciphertext integrity mismatch')
        age = (now - packet.utc(body['captured_at'])).total_seconds()
        if not 0 <= age <= 30 * 60:
            raise ValueError('packet capture expired or future')
        before = self.checkpoint()
        try:
            for _ in range(3):
                parent, old = self.read()
                if old:
                    if packet.utc(old['captured_at']) > packet.utc(body['captured_at']):
                        return {'status': 'skipped_newer', 'commit': parent}
                    if old['captured_at'] == body['captured_at']:
                        if old['ciphertext_sha256'] != body['ciphertext_sha256']:
                            raise ValueError('capture timestamp collision')
                        return {'status': 'unchanged', 'commit': parent}
                with tempfile.TemporaryDirectory(prefix='mnq-git-index-') as temporary:
                    env = dict(self.env, GIT_INDEX_FILE=str(Path(temporary) / 'index'))
                    self.git('read-tree', '--empty', env=env)
                    for name in sorted(FILES):
                        blob = self.git('hash-object', '-w', '--stdin', data=(output / name).read_bytes()).stdout.decode().strip()
                        self.git('update-index', '--add', '--cacheinfo', '100644,' + blob + ',' + name, env=env)
                    tree = self.git('write-tree', env=env).stdout.decode().strip()
                    command = ['-c', 'user.name=github-actions[bot]', '-c',
                               'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit-tree', tree]
                    if parent:
                        command += ['-p', parent]
                    commit = self.git(*command, data=b'Publish encrypted MNQ source packet\n').stdout.decode().strip()
                pushed = self.git('push', 'origin', commit + ':' + self.ref, check=False)
                if pushed.returncode == 0:
                    return {'status': 'published', 'commit': commit}
            raise RuntimeError('cache push failed after three non-force attempts')
        finally:
            if self.checkpoint() != before:
                raise RuntimeError('checkout HEAD or original index changed')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=Path('.'))
    parser.add_argument('--certificate', type=Path, required=True)
    args = parser.parse_args(argv)
    ref = os.environ.get('GITHUB_REF')
    event = os.environ.get('GITHUB_EVENT_NAME')
    if (os.environ.get('GITHUB_REPOSITORY') != 'baiyunzhi/-xiaoyuan-pages'
            or ref not in REFS or event not in {'push', 'schedule', 'workflow_dispatch'}
            or event == 'schedule' and ref != 'refs/heads/main'):
        raise ValueError('workflow repository, event or ref not allowed')
    cache = Cache(args.repo, REFS[ref])
    _, cached = cache.read()
    now = datetime.now(timezone.utc)
    if event == 'schedule' and accepted(cached, fetch_ack(), now):
        print(json.dumps({'status': 'accepted_today', 'branch': REFS[ref]}))
        return 0
    import worker
    with tempfile.TemporaryDirectory(prefix='mnq-encrypted-') as output:
        body = worker.acquire(args.certificate, output)
        result = cache.publish(output, datetime.now(timezone.utc))
    print(json.dumps(dict(result, branch=REFS[ref], captured_at=body['captured_at'],
                          ciphertext_sha256=body['ciphertext_sha256'])))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'failed', 'error_type': type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
