"""Offline backup and restore. Never overwrites a running or populated target."""
import argparse
import hashlib
import json
import os
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

from jmbot.core.process_lease import ProcessLease


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def snapshot(source, target):
    source, target = Path(source).resolve(), Path(target).resolve()
    if target == source or target.is_relative_to(source):
        raise ValueError('snapshot must be outside the live data directory')
    target.mkdir(parents=True, exist_ok=False)
    target.chmod(0o700)
    manifest = {'schema': 1, 'files': {}, 'sqlite': {}}
    try:
        for path in sorted(source.rglob('*')):
            if not path.is_file() or path.is_symlink() or path.name.endswith(('-wal', '-shm', '.lock', '.log')) or path.name == 'ready' or 'control' in path.relative_to(source).parts:
                continue
            relative = path.relative_to(source)
            destination = target / 'data' / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with path.open('rb') as stream:
                sqlite = stream.read(16) == b'SQLite format 3\x00'
            if sqlite:
                with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as old, closing(sqlite3.connect(destination)) as new:
                    old.backup(new)
                    if new.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                        raise ValueError('snapshot integrity check failed')
                    manifest['sqlite'][str(relative).replace('\\', '/')] = {row[0]: new.execute('SELECT count(*) FROM "' + row[0].replace('"', '""') + '"').fetchone()[0] for row in new.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            else:
                shutil.copy2(path, destination)
            destination.chmod(0o600)
            manifest['files'][str(destination.relative_to(target)).replace('\\', '/')] = digest(destination)
        (target / 'snapshot.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
        return manifest
    except Exception:
        # Keep partial output for diagnosis, explicitly unusable without manifest.
        raise


def verify(source):
    source = Path(source).resolve()
    manifest = json.loads((source / 'snapshot.json').read_text(encoding='utf-8'))
    if manifest.get('schema') != 1:
        raise ValueError('unsupported snapshot')
    for name, expected in manifest['files'].items():
        from pathlib import PurePosixPath
        relative = PurePosixPath(name)
        if relative.is_absolute() or not relative.parts or any(part in {'..', '.'} or ':' in part or '\\' in part for part in relative.parts):
            raise ValueError('invalid snapshot path')
        path = (source / name).resolve()
        if not path.is_relative_to(source) or not path.is_file() or digest(path) != expected:
            raise ValueError('snapshot file missing or hash mismatch')
    return manifest


def restore(source, target):
    source, target = Path(source).resolve(), Path(target).resolve()
    manifest = verify(source)
    target.mkdir(parents=True, exist_ok=False)
    for name in manifest['files']:
        destination = (target / name).resolve()
        if not destination.is_relative_to(target):
            raise ValueError('invalid restore destination')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / name, destination)
        destination.chmod(0o600)
    return {'restored': len(manifest['files']), 'directory': str(target)}


def main():
    parser = argparse.ArgumentParser(description='JMbot offline backup / isolated restore')
    parser.add_argument('operation', choices=['backup', 'verify', 'restore', 'preserve-rollback'])
    parser.add_argument('--source', required=True)
    parser.add_argument('--target')
    args = parser.parse_args()
    if args.operation == 'verify':
        result = verify(args.source)
    elif args.operation in {'backup', 'preserve-rollback'}:
        if not args.target:
            parser.error('--target is required')
        # Operators stop senders first. This lock rejects another migration.
        lock_root = Path(os.environ.get('JM_BOT_RUNTIME_LOCK_DIR', args.source))
        lease = ProcessLease(lock_root / 'qq-sender.lock')
        try:
            result = snapshot(args.source, args.target)
        finally:
            lease.close()
    else:
        if not args.target:
            parser.error('--target is required')
        target = Path(args.target).resolve()
        migration_lease = ProcessLease(target.parent / (target.name + '.migration.lock'))
        try:
            result = restore(args.source, target)
        finally:
            migration_lease.close()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
