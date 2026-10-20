"""The Server Agent's own ledger for a Task it may resume (§5.5, §9.3), chained as a-MCP §8 seals records.

One partition holds one Task. §5.5 states what is written, not its form: each entry is a JSON object named by its
`entry` member. The endpoint's credentials are never written (§13.2).
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Literal

import anyio
from auditable_mcp import GENESIS_HASH, WIRE, Ledger, LedgerRepository, WireModel, compute_record_hash
from pydantic import Field, TypeAdapter, ValidationError

from auditable_a2a.models import JournaledRequest

logger = logging.getLogger(__name__)

JournalEntry = dict[str, object]
"""One entry of the own ledger, named by its `entry` member."""

_Id = Annotated[str, Field(min_length=1)]


class _KeySet(WireModel):
    """A JWK Set."""

    keys: list[dict[str, object]]
    # end class


class _Session(WireModel):
    """The first entry: the Task, its `auditRequest` without credentials, and the keys the session runs under."""

    entry: Literal['session']
    taskId: _Id
    request: JournaledRequest
    keyId: _Id | None = None
    hostKeySnapshot: _KeySet | None = None
    # end class


class _Sent(WireModel):
    """An event about to be sent."""

    entry: Literal['sent']
    event: dict[str, object]
    # end class


class _Response(WireModel):
    """An Attempt Response, before it is acted on."""

    entry: Literal['response']
    id: _Id
    response: dict[str, object]
    # end class


class _Performing(WireModel):
    """An access about to be performed."""

    entry: Literal['performing']
    id: _Id
    # end class


class _Record(WireModel):
    """An attempt about to be sent for a record that is not an access (§8.1): completed, never reported on."""

    entry: Literal['record']
    id: _Id
    # end class


class _Resolved(WireModel):
    """How an access resolved."""

    entry: Literal['resolved']
    id: _Id
    outcome: Literal['success', 'failed']
    # end class


class _Acked(WireModel):
    """An outcome the audit host acknowledged."""

    entry: Literal['acked']
    id: _Id
    # end class


class _Close(WireModel):
    """The close, about to be sent."""

    entry: Literal['close']
    # end class


_ENTRY: TypeAdapter[_Session | _Sent | _Response | _Performing | _Record | _Resolved | _Acked | _Close] = TypeAdapter(
    Annotated[
        _Session | _Sent | _Response | _Performing | _Record | _Resolved | _Acked | _Close,
        Field(discriminator='entry'),
    ]
)


def _system_now() -> str:
    """The current time, as the ledger's `host_ts`."""
    return datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    # end def


class SelfLedgerError(Exception):
    """The Server Agent's own ledger could not be written, or could not be restored as written (§5.5)."""

    # end class


class SelfLedger:
    """One Task's partition of the Server Agent's own ledger (§5.5)."""

    def __init__(self, repository: LedgerRepository, partition: str, now: Callable[[], str]) -> None:
        """Bind the partition; use `open`, which continues the chain from its persisted tail."""
        self._repository = repository
        self._ledger = Ledger(partition)
        self._now = now
        self._lock = anyio.Lock()
        # Set while an append's fate is unknown, so the next write reads the tail first.
        self._tail_uncertain = False
        # end def

    @classmethod
    async def open(
        cls, repository: LedgerRepository, partition: str, now: Callable[[], str] = _system_now
    ) -> 'SelfLedger':
        """Open the partition, continuing the chain from its persisted tail.

        Args:
            repository: Where the partition is kept.
            partition: The Task's partition.
            now: The clock of each entry's `host_ts`.

        Returns:
            The ledger, ready to write after its last entry.

        Raises:
            SelfLedgerError: The partition's tail could not be read.
        """
        ledger = cls(repository, partition, now)
        await ledger._reload()
        return ledger
        # end def

    @property
    def partition(self) -> str:
        """The Task's partition."""
        return self._ledger.partition
        # end def

    async def write(self, entry: JournalEntry) -> None:
        """Durably append one entry, after every earlier one.

        Raises:
            SelfLedgerError: The entry was not written; what it would have preceded must not happen.
        """
        async with self._lock:
            if self._tail_uncertain:
                await self._reload()
                # end if
            record = self._ledger.seal(entry, self._now())
            self._tail_uncertain = True
            try:
                await self._repository.append(self.partition, record)
            except Exception as error:
                # The append may have landed before it failed; the tail decides where the chain continues.
                try:
                    await self._reload()
                except SelfLedgerError:
                    logger.exception('the own ledger tail could not be read back after a failed append')
                    # end try
                raise SelfLedgerError(f'the own ledger did not take a {entry["entry"]} entry') from error
                # end try
            self._ledger.commit(record)
            self._tail_uncertain = False
            # end async with
        # end def

    async def _reload(self) -> None:
        """Continue the chain from the persisted tail.

        Raises:
            SelfLedgerError: The tail could not be read; the next write tries again.
        """
        try:
            tail = await self._repository.load_tail(self.partition)
        except Exception as error:
            self._tail_uncertain = True
            raise SelfLedgerError(f'the own ledger tail of {self.partition} could not be read') from error
            # end try
        self._ledger.resume_from(tail)
        self._tail_uncertain = False
        # end def

    async def entries(self) -> list[JournalEntry]:
        """Every entry of the partition, after recomputing its chain (a-MCP §8.2).

        Raises:
            SelfLedgerError: The chain does not recompute, or an entry is not one this SDK writes: the ledger
                cannot be restored (§5.5).
        """
        try:
            records = await self._repository.read_all(self.partition)
        except Exception as error:
            raise SelfLedgerError(f'the own ledger {self.partition} could not be read') from error
            # end try
        previous = GENESIS_HASH
        for index, record in enumerate(records):
            if (
                record.seq != index
                or record.previous_hash != previous
                or record.record_hash
                != compute_record_hash(record.event, record.seq, record.host_ts, record.previous_hash)
            ):
                raise SelfLedgerError(f"the own ledger's chain breaks at seq {index} of {self.partition}")
                # end if
            try:
                _ENTRY.validate_python(record.event, context=WIRE)
            except ValidationError as error:
                raise SelfLedgerError(
                    f'the own ledger holds an entry it did not write at seq {record.seq} of {self.partition}'
                ) from error
                # end try
            previous = record.record_hash
            # end for
        return [record.event for record in records]
        # end def

    # end class
