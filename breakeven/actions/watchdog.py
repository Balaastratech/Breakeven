"""The revert watchdog — `INV-S01`.

Runs as its own OS process, spawned by :func:`breakeven.actions.executor.execute_action`
and never joined, so it outlives whatever process spawned it. It shares no Python object
with its parent — it re-imports :mod:`breakeven.actions.executor` fresh in this process
and reads the action's state from the JSON file on disk, which is the only channel the
two processes share. That is the entire point: nothing about this process depends on the
one that started it still being alive.

Entry point:

.. code-block:: bash

    python -m breakeven.actions.watchdog <action_id> <deadline_epoch> <state_dir>

Sleeps until ``deadline_epoch``, then reverts ``action_id``. If it has already been
reverted early by a direct :func:`~breakeven.actions.executor.revert_action` call, the
revert it performs here is a no-op — idempotency is :func:`revert_action`'s job, not
this module's.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

from breakeven.actions import executor


def _record_failure(state_dir: Path, action_id: str, error: BaseException) -> None:
    """Write what killed the revert to a file, instead of letting it vanish.

    `silent-failure-hunter`, task 10: this process is launched with its stdout/stderr
    discarded (`executor._spawn_watchdog`) precisely because nobody is attached to a
    terminal to read them — which means an uncaught exception here previously left no
    trace anywhere. This is the trace: a sidecar file next to the action's own state
    file, written whenever the revert this process exists to perform did not happen.

    **This function never raises**, and that is the whole of its second fix (task 10's
    review): it is called from :func:`main`'s ``except`` block, immediately before the
    bare ``re-raise``. An exception escaping *here* would replace the revert's real
    failure with an I/O error, escape ``main()`` uncaught, and be printed to a
    ``DEVNULL`` stderr — leaving nothing at all, which is exactly what the sidecar was
    invented to prevent, recurring one layer deeper. ``state_dir`` is the thing most
    likely to be gone by the time this process wakes, hours after it was spawned, so the
    fallback is deliberately somewhere else.
    """
    # `_write_text_atomic` and `_action_file` are package-internal helpers of the sibling
    # module this watchdog exists to serve, not a foreign class's privates. Reusing them
    # is the point: the sidecar is written by the same atomic write and validated by the
    # same one `action_id` guard as every other durable file in this kernel.
    # pylint: disable=protected-access
    payload = json.dumps(
        {
            "action_id": action_id,
            "error": repr(error),
            "at_epoch": time.time(),
        }
    )

    try:
        executor._write_text_atomic(
            executor._action_file(state_dir, action_id, ".watchdog_error.json"), payload
        )
        return
    except Exception:  # pylint: disable=broad-except
        pass

    try:
        executor._write_text_atomic(
            executor._action_file(
                Path(tempfile.gettempdir()),
                f"breakeven-watchdog-{action_id}",
                ".error.json",
            ),
            payload,
        )
    except Exception:  # pylint: disable=broad-except
        # ponytail: two locations, best-effort, then stop. If neither the action's own
        # state directory nor the system temp directory can be written, the non-zero
        # exit code `main()`'s re-raise produces is the last signal available — and
        # searching further for somewhere writable is an unbounded chase with no
        # reader at the end of it.
        pass


def main(argv: list[str]) -> int:
    """Sleep until the deadline the executor gave us, then revert. ``argv`` is
    ``[prog, action_id, deadline_epoch, state_dir]`` — see the module docstring."""
    action_id, deadline_epoch_text, state_dir_text = argv[1], argv[2], argv[3]
    deadline_epoch = float(deadline_epoch_text)
    state_dir = Path(state_dir_text)

    remaining = deadline_epoch - time.time()
    if remaining > 0:
        time.sleep(remaining)

    try:
        executor.revert_action(action_id, state_dir=state_dir)
    except Exception as error:
        # This process's only job is to revert. A failure here must leave a record, not
        # a silently discarded traceback — then re-raise, so a non-zero exit code is
        # still the process's honest final word. `_record_failure` cannot raise, so this
        # `raise` always executes and the error that leaves is always the revert's own.
        _record_failure(state_dir, action_id, error)
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
