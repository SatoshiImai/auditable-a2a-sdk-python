"""What the walk's processes share: a ledger kept in files, the published JWKs, and the listening socket.

A process writes `WALK_URL=<url>` once it listens, and binds to `WALK_PORT` when given, so a restarted Server
Agent keeps its URL and with it its key ids (§5.2, §10.2).
"""

import json
import os
import socket
import ssl
import sys
from pathlib import Path
from typing import Any

from auditable_mcp import RepositoryError, SealedRecord
from auditable_mcp.l2 import public_jwk
from auditable_mcp.l2.algorithms import KeyRole, SignatureAlgorithm

URL_LINE = 'WALK_URL='


class FileLedgerRepository:
    """A `LedgerRepository` that keeps each partition as a JSON-lines file, so that it survives the process."""

    def __init__(self, directory: Path) -> None:
        """Keep the partitions in `directory`."""
        self._directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        # end def

    def _path(self, partition: str) -> Path:
        """The file of one partition."""
        return self._directory / f'{partition.replace("/", "_")}.jsonl'
        # end def

    async def append(self, partition: str, record: SealedRecord) -> None:
        """Append `record`, conditionally on its being the partition's next position."""
        records = await self.read_all(partition)
        expected = records[-1].seq + 1 if records else 0
        if record.seq != expected:
            raise RepositoryError(f'seq {record.seq} is not the next position {expected} of {partition}')
            # end if
        with self._path(partition).open('a', encoding='utf-8') as file:
            file.write(json.dumps(record.to_dict(), ensure_ascii=False) + '\n')
            file.flush()
            os.fsync(file.fileno())
            # end with
        # end def

    async def load_tail(self, partition: str) -> SealedRecord | None:
        """The partition's last record, or None."""
        records = await self.read_all(partition)
        return records[-1] if records else None
        # end def

    async def read_all(self, partition: str) -> list[SealedRecord]:
        """Every record of the partition, in order."""
        path = self._path(partition)
        if not path.exists():
            return []
            # end if
        lines = path.read_text('utf-8').splitlines()
        return [SealedRecord.from_dict(json.loads(line)) for line in lines if line]
        # end def

    # end class


def ordinary_jwk(kid: str, public_key: Any, role: KeyRole) -> dict[str, object]:
    """Publish a key as an ordinary JWK, as a Server Agent's or audit host's JWKS holds it (§10.2)."""
    jwk = public_jwk(kid, public_key, SignatureAlgorithm.ED25519, role)
    return {key: value for key, value in jwk.items() if key != 'amcp_role'}
    # end def


def listening_socket() -> socket.socket:
    """A loopback socket on `WALK_PORT`, or on a free port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', int(os.environ.get('WALK_PORT', '0'))))
    sock.listen(64)
    sock.set_inheritable(True)
    return sock
    # end def


def announce(url: str) -> None:
    """Tell the walk where this process listens."""
    sys.stdout.write(f'{URL_LINE}{url}\n')
    sys.stdout.flush()
    # end def


def trust() -> ssl.SSLContext:
    """The TLS context that trusts the walk's certificate authority (`WALK_CA`)."""
    return ssl.create_default_context(cafile=os.environ['WALK_CA'])
    # end def
