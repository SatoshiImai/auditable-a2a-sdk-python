"""Vendor the normative Auditable A2A spec artifacts into this repository.

The JSON Schema (`schema/`) and conformance vectors (`vectors/`) are copied from the `auditable-a2a` repository.

Usage:
    python scripts/sync_spec.py            # copy source -> vendored spec/
    python scripts/sync_spec.py --check    # verify vendored == source (CI drift gate); no writes

The source location resolves in this order: `--source` argument, `AA2A_SPEC_SRC` environment
variable, then the default sibling checkout `../auditable-a2a/spec`.
"""

import argparse
import filecmp
import logging
import os
import shutil
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('sync_spec')

VENDORED_SUBDIRS = ('schema', 'vectors')

_REPO_ROOT = Path(__file__).resolve().parents[1]
_VENDORED_SPEC_DIR = _REPO_ROOT / 'spec'
_DEFAULT_SOURCE = _REPO_ROOT.parent / 'auditable-a2a' / 'spec'


def _roots(source: Path) -> list[tuple[Path, Path]]:
    """Return the (source, vendored) directory pairs, in the order they are copied and checked."""
    return [(source / subdir, _VENDORED_SPEC_DIR / subdir) for subdir in VENDORED_SUBDIRS]
    # end def


def resolve_source(cli_source: str | None) -> Path:
    """Resolve the source spec directory from CLI arg, env var, then the default sibling checkout.

    Args:
        cli_source: The `--source` argument value, or None.

    Returns:
        The resolved absolute path to the source spec directory.

    Raises:
        FileNotFoundError: If the resolved directory does not exist.
    """
    raw = cli_source or os.environ.get('AA2A_SPEC_SRC') or str(_DEFAULT_SOURCE)
    source = Path(raw).expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(f'spec source directory not found: {source}')
        # end if
    return source
    # end def


def _iter_pairs(source: Path) -> list[tuple[Path, Path]]:
    """Return every (source file, vendored file) pair the two roots hold, in a stable order."""
    pairs: list[tuple[Path, Path]] = []
    for src_dir, dst_dir in _roots(source):
        if not src_dir.is_dir():
            continue
            # end if
        for src_path in sorted(src_dir.rglob('*.json')):
            pairs.append((src_path, dst_dir / src_path.relative_to(src_dir)))
            # end for
        # end for
    return pairs
    # end def


def check(source: Path) -> bool:
    """Verify the vendored copies match the source byte-for-byte.

    Args:
        source: The source spec directory.

    Returns:
        True if every vendored copy is in sync, False otherwise.
    """
    pairs = _iter_pairs(source)
    expected = {dst for _src, dst in pairs}
    ok = True

    for src_path, dst_path in pairs:
        if not dst_path.is_file():
            logger.error('missing in vendored copy: %s', dst_path.relative_to(_REPO_ROOT))
            ok = False
        elif not filecmp.cmp(src_path, dst_path, shallow=False):
            logger.error('content drift: %s', dst_path.relative_to(_REPO_ROOT))
            ok = False
            # end if
        # end for

    for _src_dir, dst_dir in _roots(source):
        if not dst_dir.is_dir():
            continue
            # end if
        for stale in sorted(dst_dir.rglob('*.json')):
            if stale not in expected:
                logger.error('stale file in vendored copy (not in source): %s', stale.relative_to(_REPO_ROOT))
                ok = False
                # end if
            # end for
        # end for

    if ok:
        logger.info('vendored copies are in sync (%d files)', len(pairs))
        # end if
    return ok
    # end def


def sync(source: Path) -> int:
    """Copy the normative subdirectories from source into the vendored spec directory.

    Args:
        source: The source spec directory.

    Returns:
        The number of files copied.
    """
    for _src_dir, dst_dir in _roots(source):
        if dst_dir.exists():
            shutil.rmtree(dst_dir)
            # end if
        # end for
    copied = 0
    for src_path, dst_path in _iter_pairs(source):
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dst_path)
        copied += 1
        # end for
    logger.info('vendored %d files from %s', copied, source)
    return copied
    # end def


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument vector for testing; defaults to sys.argv.

    Returns:
        A process exit code (0 on success, 1 on drift/failure).
    """
    parser = argparse.ArgumentParser(description='Vendor the normative Auditable A2A spec artifacts.')
    parser.add_argument('--check', action='store_true', help='verify sync without writing (CI gate)')
    parser.add_argument('--source', default=None, help='source spec directory (overrides AA2A_SPEC_SRC)')
    args = parser.parse_args(argv)

    source = resolve_source(args.source)
    if args.check:
        return 0 if check(source) else 1
        # end if
    sync(source)
    return 0
    # end def


if __name__ == '__main__':
    sys.exit(main())
    # end if
