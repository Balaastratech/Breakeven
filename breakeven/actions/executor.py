"""The action executor — F-ACT-21, F-ACT-23.

The policy engine (`breakeven.policy.engine`) decides whether an action may run. This
module is what runs it and what reverts it if nobody proves it worked in time. The
revert is scheduled by a mechanism that outlives whatever process called
:func:`execute_action`, never by an agent loop. `INV-S02`: no model call anywhere here,
same as the policy engine.

The mechanism, and why it looks like this, is `docs/DECISIONS.md` `D-S34`. In short: at
execution time this module spawns a detached watchdog **subprocess** — not a thread, not
an ``asyncio`` task — that holds the TTL timer and, on expiry, calls back into
:func:`revert_action` re-imported fresh in its own process. The two processes never share
Python objects; they share only a small JSON state file per ``action_id``. That is what
makes the revert survive the caller dying: there is nothing left inside the caller for it
to depend on.

This module deliberately does not know what an action's effect *means*. The caller
supplies the concrete change as a ``(target_path, new_value)`` pair — a file standing in,
in this walking skeleton, for the one write a real action would make to the control
plane. What is generic and load-bearing is the scheduling, the idempotent revert, and the
process boundary — not the payload.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from breakeven.policy.engine import ActionResult

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl  # pylint: disable=import-error

# An `action_id` is used as a filename component, so it is validated as one. From task 13
# a model's proposal populates this field, at which point it is attacker-influenced data
# being interpolated into a path: `"../../evil"` escapes `state_dir`, and an id starting
# with a separator resolves to an absolute path, discarding `state_dir` entirely.
_SAFE_ACTION_ID = re.compile(r"[A-Za-z0-9_-]+")

# An idempotency key is also used as a filename component, and it arrives here from
# further upstream than `action_id` does: `breakeven.policy.engine.idempotency_key`
# derives it partly from `Incident.failure_signature`, which a model's proposal
# populates. Only a digest that function could actually have produced is accepted — the
# same trust-boundary reasoning as `_SAFE_ACTION_ID`, one step earlier in the chain.
_SAFE_IDEMPOTENCY_KEY = re.compile(r"[0-9a-f]{64}")

# Gap #2 (`GAPS.md`): with no timeout, a hung undo target blocks `_http_delete` forever —
# silently, since nothing else is watching this call. Same rationale and value as
# `blocklist._HTTP_TIMEOUT_SECONDS`.
_HTTP_TIMEOUT_SECONDS = 60


class DuplicateActionError(ValueError):
    """Raised instead of applying an action whose idempotency key is already held.

    F-ACT-25's *"a retry can never double-apply"* is enforced by refusing, not by
    silently returning: `F-VER-10`'s *"applied exactly once"* means the replay resolves
    to the one already-applied effect, so this exception names the ``action_id`` that
    holds it. A caller that wanted to treat a replay as success can, having been told
    which action to look at; a caller that silently swallowed a no-op could not.

    A :class:`ValueError` subclass so that every existing caller of
    :func:`execute_action` — which already raises :class:`ValueError` for a re-executed
    ``action_id`` — keeps handling this the same way, including the operator route that
    maps :class:`ValueError` to HTTP 409.
    """

    def __init__(
        self, idempotency_key: str, holder_action_id: str, attempted_action_id: str
    ) -> None:
        super().__init__(
            f"action {attempted_action_id!r} was refused: idempotency key "
            f"{idempotency_key} is already held by action {holder_action_id!r}, which "
            f"has not been reverted"
        )
        self.idempotency_key = idempotency_key
        self.holder_action_id = holder_action_id
        self.attempted_action_id = attempted_action_id


def _action_file(state_dir: Path, action_id: str, suffix: str) -> Path:
    """The one place any per-action path is built, and therefore the one place
    ``action_id`` is checked.

    Both :func:`_state_path` and :func:`_pid_path` route through here, as does the
    watchdog's error sidecar — so the id the watchdog receives on ``argv`` is checked by
    the same guard as the one the executor was handed, without the check being written
    three times.
    """
    if not _SAFE_ACTION_ID.fullmatch(action_id):
        raise ValueError(
            f"action_id {action_id!r} is not a safe filename component; "
            f"expected {_SAFE_ACTION_ID.pattern}"
        )
    return state_dir / f"{action_id}{suffix}"


def _state_path(state_dir: Path, action_id: str) -> Path:
    return _action_file(state_dir, action_id, ".json")


def _pid_path(state_dir: Path, action_id: str) -> Path:
    """The watchdog's pid, in its own file — deliberately not a field in the state
    record.

    `silent-failure-hunter`, task 10: :func:`revert_action` reads and rewrites the state
    record (``status``, ``reverted_at_epoch``). If the pid also lived there,
    :func:`execute_action` attaching it after spawning would be a second writer racing
    that same record — for a near-zero TTL, the watchdog can finish a revert in the gap
    between :func:`execute_action`'s read and its write, and that second write would
    silently clobber the revert back to ``"executed"``. A separate, write-once file has
    no such writer to race.
    """
    return _action_file(state_dir, action_id, ".watchdog_pid")


def _check_idempotency_key(idempotency_key: str) -> str:
    if not _SAFE_IDEMPOTENCY_KEY.fullmatch(idempotency_key):
        raise ValueError(
            f"idempotency key {idempotency_key!r} is not a key "
            f"breakeven.policy.engine.idempotency_key could have produced; expected "
            f"{_SAFE_IDEMPOTENCY_KEY.pattern}"
        )
    return idempotency_key


def _idempotency_claim_path(state_dir: Path, idempotency_key: str) -> Path:
    """The file recording which ``action_id`` currently holds ``idempotency_key``.

    The seen-set is one small file per *live* key rather than a single shared index: the
    per-key file can be claimed and released under a per-key lock, so two actions for two
    different situations never contend, and a torn write can only ever affect the one key
    it belongs to. It sits in ``state_dir`` alongside the per-action records and is
    written by the same :func:`_write_text_atomic`, so it inherits their crash-safety
    rather than introducing a second durability mechanism.
    """
    return _action_file(
        state_dir, f"key_{_check_idempotency_key(idempotency_key)}", ".idempotency.json"
    )


def _idempotency_lock_path(state_dir: Path, idempotency_key: str) -> Path:
    return _action_file(
        state_dir, f"key_{_check_idempotency_key(idempotency_key)}", ".idempotency.lock"
    )


def _read_claim_holder(claim_path: Path) -> str | None:
    """Return the ``action_id`` in ``claim_path``, or ``None`` if there is no claim.

    ``None`` means *no claim file* and nothing else. A claim file that exists but cannot be
    read as one is **not** treated as absent — that would let an action apply on top of one
    that may still be live, which is the double-apply F-ACT-25 exists to prevent, reached
    through a torn file instead of a retry. It raises instead, as a :class:`ValueError`
    naming the file: :class:`DuplicateActionError` is a :class:`ValueError` precisely so the
    operator route maps a refusal to HTTP 409, and a bare ``KeyError`` escaping the same
    call would bypass that mapping and name nothing.
    """
    try:
        claim = json.loads(claim_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as error:
        raise ValueError(
            f"idempotency claim {claim_path} is not readable JSON: {error}"
        ) from error
    try:
        return claim["action_id"]
    except (KeyError, TypeError) as error:
        raise ValueError(
            f"idempotency claim {claim_path} has no action_id field; it cannot be "
            f"established whether the key is held"
        ) from error


def _key_is_still_held(state_dir: Path, holder_action_id: str) -> bool:
    """Does ``holder_action_id`` still have a claim on the key it recorded?

    ``False`` in exactly two cases, and both are deliberate:

    * **the holder has no state record** — the crash window between claiming a key and
      writing that record. No revert will ever run for an action that does not exist, so
      without this the key would be blocked permanently and the situation would become
      unactionable forever. This is why the claim and the holder's state record are written
      under **one** hold of the per-key lock (see :func:`_claim_idempotency_key`): the rule
      is only safe while no other claimant can observe that intermediate state.
    * **the holder is ``"reverted"``** — assertion 4 of `PLAN.md` Task 8: idempotency is
      per-application, not a permanent tombstone, "or the TTL revert leaves the platform
      unfixable".

    ``"reverting"`` counts as **still held**. The world is not restored yet, so applying a
    second time would race the in-flight restore and could have its new value overwritten
    by the revert's ``previous_value`` write.
    """
    holder_state_path = _state_path(state_dir, holder_action_id)
    try:
        # Read rather than `exists()`-then-read: the rollback path in `execute_action`
        # unlinks a state record without the per-key lock, so a check-then-read would
        # raise `FileNotFoundError` in the gap and refuse a legitimate action with a
        # confusing error while nothing actually holds the key.
        return _read_state(holder_state_path)["status"] != "reverted"
    except FileNotFoundError:
        return False


@contextlib.contextmanager
def _claim_idempotency_key(state_dir: Path, idempotency_key: str, action_id: str):
    """Hold ``idempotency_key`` for ``action_id`` across the body, or raise
    :class:`DuplicateActionError` without entering it.

    **The per-key lock is held for the whole body, and the caller writes the holder's state
    record inside it.** Checking the key and taking it under one lock is not sufficient on
    its own: :func:`_key_is_still_held` must report a claim whose holder has no state record
    as free (see its docstring), so releasing the lock between the claim and the record
    lets a second claimant observe that gap, conclude the key is free, take it over, and
    apply — two mutations and two armed watchdogs for one situation, with no crash
    anywhere. Found by this task's own `silent-failure-hunter` pass, reproduced with two
    real processes in ``tests/test_actions_idempotency.py``'s
    ``test_a_second_process_cannot_claim_while_the_first_is_between_claim_and_record``.

    Same OS-level advisory lock as :func:`revert_action` uses (`D-S44`/`D-S45`), so it is
    likewise released by the kernel when a holding process dies and can never permanently
    block a later caller. The action's own mutation stays **outside** the body: by then the
    state record exists and reads ``"executed"``, so the claim is held on the record's
    authority rather than the lock's, and no lock is held across a control-plane write.

    Any exception from the body releases the claim before propagating — nothing was
    recorded, so nothing may be held.
    """
    claim_path = _idempotency_claim_path(state_dir, idempotency_key)
    with _locked(_idempotency_lock_path(state_dir, idempotency_key)):
        holder_action_id = _read_claim_holder(claim_path)
        if holder_action_id is not None and _key_is_still_held(
            state_dir, holder_action_id
        ):
            raise DuplicateActionError(idempotency_key, holder_action_id, action_id)
        _write_text_atomic(
            claim_path,
            json.dumps({"idempotency_key": idempotency_key, "action_id": action_id}),
        )
        try:
            yield
        except BaseException as body_error:
            # Already inside the lock, so release without taking it again.
            #
            # `silent-failure-hunter`, this session's review: `_drop_claim` itself can
            # raise (`_read_claim_holder` raises `ValueError` on a malformed claim file,
            # or `OSError` on a torn read) — unguarded, that exception would silently
            # replace `body_error` and the trailing `raise` would never run, hiding
            # whatever actually failed inside the body. No control-plane mutation has
            # happened yet at this point (the claim precedes it), so failing toward
            # denial by re-raising the original error is safe; the cleanup failure is
            # chained rather than swallowed.
            try:
                _drop_claim(claim_path, action_id)
            except (OSError, ValueError) as cleanup_error:
                raise body_error from cleanup_error
            raise


def _drop_claim(claim_path: Path, action_id: str) -> None:
    """Delete ``claim_path`` if it still names ``action_id``. Caller holds the key lock.

    Compare before deleting: a later action may already have taken the key over, and
    deleting *its* claim would silently reopen the double-apply window for an action that
    is genuinely live.
    """
    if _read_claim_holder(claim_path) != action_id:
        return
    claim_path.unlink(missing_ok=True)


def _release_idempotency_key(
    state_dir: Path, idempotency_key: str, action_id: str
) -> None:
    """Give up ``action_id``'s claim on ``idempotency_key``, if it is still ours."""
    claim_path = _idempotency_claim_path(state_dir, idempotency_key)
    with _locked(_idempotency_lock_path(state_dir, idempotency_key)):
        _drop_claim(claim_path, action_id)


def _release_claim_of(state: dict, state_dir: Path, action_id: str) -> None:
    """Release the idempotency claim recorded on ``state``, if it holds one — F-ACT-25.

    Called only once ``state`` has reached ``"reverted"``: the key is released after the
    world is genuinely restored, so a replay can never overlap an in-flight revert.
    ``"reverting"`` deliberately does not release.

    **A failure here is recorded, and deliberately does not propagate out of
    :func:`revert_action`.** It is not swallowed — it gets its own durable sidecar, named
    for what actually failed. But it must not be *mistaken for a failed revert*: by this
    point the world is restored and the record says ``"reverted"``, and the watchdog turns
    any exception leaving :func:`revert_action` into
    ``<action_id>.watchdog_error.json``, whose documented meaning is "the revert this
    process exists to perform did not happen". For a product whose claim is "auto-reverts
    anything it cannot prove worked", reporting a successful revert as failed is the
    worst-direction lie available — an operator reads it and re-applies by hand. The two
    are separate facts and get separate records.

    Nor is it permanent: a claim whose holder reads ``"reverted"`` is no longer honoured by
    :func:`_key_is_still_held`, so the next action for the same situation takes it over.
    Only the anticipated I/O and malformed-claim failures are caught — anything else is a
    genuine surprise and still propagates.
    """
    held_idempotency_key = state.get("idempotency_key")
    if held_idempotency_key is None:
        return
    try:
        _release_idempotency_key(state_dir, held_idempotency_key, action_id)
    except (OSError, ValueError) as error:
        _record_release_failure(state_dir, action_id, held_idempotency_key, error)


def _record_release_failure(
    state_dir: Path, action_id: str, idempotency_key: str, error: BaseException
) -> None:
    """Write why a claim release failed, next to the action's own state record.

    Best-effort and never raising, for the same reason
    :func:`breakeven.actions.watchdog._record_failure` is: this runs inside the detached
    watchdog process, whose stdout and stderr are ``DEVNULL``, so an exception escaping
    *here* would replace a recorded bookkeeping failure with nothing at all.
    """
    try:
        _write_text_atomic(
            _action_file(state_dir, action_id, ".idempotency_release_error.json"),
            json.dumps(
                {
                    "action_id": action_id,
                    "idempotency_key": idempotency_key,
                    "error": str(error),
                    "at_epoch": time.time(),
                }
            ),
        )
    except OSError:
        # The state directory is gone or unwritable. The claim is already harmless — a
        # `"reverted"` holder is taken over by the next claimant — so there is nothing
        # left to protect and nowhere left to say so.
        pass


@contextlib.contextmanager
def _locked(lock_path: Path):
    """Hold an OS-level advisory lock on ``lock_path`` for the scope of the ``with``
    block — ``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows.

    `D-S45`: the kernel releases this lock unconditionally when the holding process's
    file descriptor/handle is torn down, including on ``SIGKILL``/``TerminateProcess`` —
    a property of *how* the lock is released, not of *how long* it is held, which is what
    lets `revert_action` narrow the lock's scope without reopening `INV-S01`'s
    permanent-block failure mode. Content is never read; the file only exists to be
    locked.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
    try:
        if sys.platform == "win32":
            # `msvcrt.locking` locks a byte range, not a whole-file description, so the
            # file must be at least one byte long before it can be locked.
            if os.fstat(fd).st_size == 0:
                try:
                    os.write(fd, b"\0")
                except OSError as write_error:
                    # Proven directly (a second real process reproduced this
                    # spontaneously in this session's own regression run): a second
                    # process can open the same brand-new, still-empty lock file in the
                    # narrow window before the first process has written its own first
                    # byte, and lose this write to `PermissionError` if the first has
                    # since gone on to lock that same byte range — Windows denies a
                    # write to a byte range a *different* handle holds locked. The
                    # first process always writes before it locks (immediately above),
                    # so a `PermissionError` here means the byte this call wanted to
                    # write is already there. Nothing left to do; fall through to
                    # (blocking) acquire the same lock. Anything else is a genuine
                    # surprise and still propagates, same reasoning as the retry loop
                    # below.
                    if write_error.errno != errno.EACCES:
                        raise
            os.lseek(fd, 0, os.SEEK_SET)
            # `LK_LOCK` is not actually unbounded: the underlying Win32 call retries for
            # ~10 attempts at ~1s each and then raises `OSError(36, "Resource deadlock
            # avoided")` if the byte range is still held — proven directly (a synthetic
            # holder + contender reproduced the raise at ~9s). `fcntl.flock(LOCK_EX)` on
            # the POSIX branch below has no such ceiling, and this function's own
            # docstring promises the same "held for the whole body" semantics on both
            # platforms. Under real contention (a second process's own hold of this same
            # per-key lock delayed past that ceiling by a loaded machine), the raw
            # `OSError` used to propagate out of `execute_action` uncaught — silently, in
            # `test_two_concurrent_executes_for_the_same_key_apply_exactly_one`'s child
            # process (`tests/test_actions_idempotency.py`), whose own
            # `except executor.DuplicateActionError` could never have caught it. Retrying
            # past that internal ceiling makes the Windows branch actually blocking,
            # matching `fcntl.flock` and this function's own contract.
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                    break
                except OSError as lock_error:
                    # `silent-failure-hunter`: only the specific ceiling this loop
                    # exists to survive is swallowed. Any other `OSError` (a closed
                    # fd, a bad byte range, a real permissions failure) is a genuine
                    # surprise and must still propagate — an unconditional `except
                    # OSError: continue` would silently retry those forever instead
                    # of surfacing them, trading a loud crash for a silent, undiagnosable
                    # hang, which is strictly worse.
                    if lock_error.errno != errno.EDEADLOCK:
                        raise
                    continue
        else:
            fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if sys.platform == "win32":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _unlink_state_after_failed_mutation(
    state_path: Path, mutation_error: OSError
) -> None:
    """Remove ``state_path`` after its mutation failed, chaining rather than masking a
    cleanup failure of its own.

    `silent-failure-hunter`, this session's review: the unlink itself can raise
    ``OSError`` too (the same disk-full/permissions condition that failed the mutation,
    or a Windows sharing violation). Unguarded, that second exception would silently
    replace ``mutation_error`` and the caller would never learn the mutation itself
    failed, while the state record stays stuck claiming ``"executed"`` with no watchdog
    ever spawned for it. A small helper rather than an inline nested ``try`` inside
    :func:`execute_action`'s own mutation-failure handler, purely to keep that function's
    local-variable count in check — no behavioural difference either way.
    """
    try:
        state_path.unlink(missing_ok=True)
    except OSError as cleanup_error:
        raise mutation_error from cleanup_error


def _read_state(state_path: Path) -> dict:
    return json.loads(state_path.read_text(encoding="utf-8"))


def _write_text_atomic(path: Path, content: str) -> None:
    """Write-then-rename, never a direct write.

    `silent-failure-hunter`, task 10: a plain ``write_text`` is not atomic — a crash or
    kill mid-write leaves a truncated file that a later reader (most dangerously, the
    watchdog at TTL expiry) fails to parse. ``Path.replace`` is an atomic rename on both
    POSIX and Windows, so a reader only ever sees the old complete content or the new
    complete content, never a partial one.
    """
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(path)


def _write_state(state_path: Path, state: dict) -> None:
    _write_text_atomic(state_path, json.dumps(state))


def _spawn_watchdog(action_id: str, deadline_epoch: float, state_dir: Path) -> int:
    """Start the revert watchdog as a genuinely separate OS process.

    Never joined, never waited on. `D-S34`: `subprocess.Popen`, not `multiprocessing` —
    the child re-imports this module from the installed package rather than receiving a
    pickled Python object, so nothing about it depends on this process staying alive.
    """
    popen_kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    # Deliberately not `with subprocess.Popen(...)`: that context manager waits on the
    # child at exit, which is precisely the coupling `INV-S01` forbids — this process
    # must return immediately, leaving the child running on its own.
    # pylint: disable=consider-using-with
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "breakeven.actions.watchdog",
            action_id,
            str(deadline_epoch),
            str(state_dir),
        ],
        **popen_kwargs,
    )
    return process.pid


def _http_delete(url: str) -> None:
    """Delete an HTTP undo target, treating an already-absent target as restored."""
    request = urllib.request.Request(url, method="DELETE")
    try:
        with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT_SECONDS) as response:
            if response.status not in {200, 204}:
                raise ValueError(f"undo DELETE {url!r} returned {response.status}")
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise


# Six arguments, five of them keyword-only and each one a distinct, required part of the
# action contract this function honours (mutation pair, HTTP-undo alternative, idempotency
# key). Collapsing them into a parameter object would add a type for one call shape and
# hide which combinations are legal, which is exactly what the guard below checks.
# pylint: disable=too-many-arguments
def execute_action(
    action: ActionResult,
    *,
    state_dir: Path,
    target_path: Path | None = None,
    new_value: str | None = None,
    undo_urls: list[str] | None = None,
    idempotency_key: str | None = None,
) -> None:
    """Apply ``action`` by writing ``new_value`` to ``target_path``, remembering
    whatever was there before, and schedule an independent revert at ``action.ttl``'s
    expiry (`INV-S01`).

    Raises :class:`ValueError` naming ``action.action_id`` if it was already executed —
    an executor call is not itself idempotent; :func:`revert_action` is.

    **Ordering is deliberate and load-bearing** (`silent-failure-hunter`, task 10): the
    durable record is written *before* ``target_path`` is mutated and *before* the
    watchdog is spawned, so a crash right after either step always leaves a state file
    that is honest about what has and has not happened yet — and a failure applying the
    mutation itself removes that record again rather than leaving it lying about an
    action that never took effect. Whether a watchdog was ever successfully scheduled is
    recorded separately, in ``<action_id>.watchdog_pid`` — see :func:`_pid_path`.

    ``idempotency_key`` is optional and defaults to today's behaviour — F-ACT-25. Passed,
    it must be a key :func:`breakeven.policy.engine.idempotency_key` produced, and the
    action is refused with :class:`DuplicateActionError` if another action already holds
    that key and has not been reverted. That is the guard the per-``action_id`` check
    above cannot be: ``action_id`` identifies a *proposal*, so two proposals for the same
    real-world situation carry different ids and both pass it. The key identifies the
    situation. Omitted, no claim is taken and nothing else here changes — which is why the
    existing `steering.py`/`ladder.py`/`blocklist.py` call sites need no edit.

    **The claim is taken before the mutation and dropped again if the mutation fails**,
    for the same reason the state record is: nothing was applied, so nothing may be held,
    and a key held by an action that never took effect would block every future attempt
    on that situation with no revert left to release it.
    """
    file_mutation = target_path is not None and new_value is not None
    http_undo = undo_urls is not None and bool(undo_urls)
    if (http_undo and (target_path is not None or new_value is not None)) or (
        not http_undo and not file_mutation
    ):
        raise ValueError(
            "provide either target_path and new_value or non-empty undo_urls"
        )
    # Validated before `state_dir` is created, so a rejected key leaves nothing behind at
    # all — the same property the `action_id` guard has.
    if idempotency_key is not None:
        _check_idempotency_key(idempotency_key)

    state_path = _state_path(state_dir, action.action_id)
    state_dir.mkdir(parents=True, exist_ok=True)
    if state_path.exists():
        raise ValueError(f"action {action.action_id!r} was already executed")

    # The claim and the state record land under one hold of the per-key lock — see
    # `_claim_idempotency_key`. `ExitStack` because there is nothing to hold when no key
    # was supplied, and the no-key path must stay exactly what it was.
    with contextlib.ExitStack() as claim:
        if idempotency_key is not None:
            claim.enter_context(
                _claim_idempotency_key(state_dir, idempotency_key, action.action_id)
            )

        previous_value = (
            target_path.read_text(encoding="utf-8")
            if target_path is not None and target_path.exists()
            else None
        )
        deadline_epoch = time.time() + action.ttl.total_seconds()

        # Record before mutating: if this process dies right after this line, the target
        # is still untouched and the state file honestly says so. Nothing is lost, because
        # nothing has happened yet.
        _write_state(
            state_path,
            {
                "action_id": action.action_id,
                "target_path": str(target_path) if target_path is not None else None,
                "previous_value": previous_value,
                "status": "executed",
                "deadline_epoch": deadline_epoch,
                "reverted_at_epoch": None,
                "undo_urls": undo_urls if http_undo else None,
                "idempotency_key": idempotency_key,
            },
        )

    try:
        if file_mutation:
            target_path.write_text(new_value, encoding="utf-8")
    except OSError as mutation_error:
        # Nothing was actually applied — remove the record instead of leaving it claim
        # an action that never took effect, which would also permanently block a retry
        # of this same `action_id` against the existence check above. The idempotency
        # claim goes with it, for the same reason and one worse: a claim outliving a
        # mutation that never landed blocks every *other* `action_id` too, and no revert
        # will ever run to release it.
        _unlink_state_after_failed_mutation(state_path, mutation_error)
        if idempotency_key is not None:
            try:
                _release_idempotency_key(state_dir, idempotency_key, action.action_id)
            except (OSError, ValueError) as release_error:
                # The mutation's own failure is what the caller needs to see; a failure
                # cleaning up after it must not replace it. Chained, never swallowed.
                _record_release_failure(
                    state_dir, action.action_id, idempotency_key, release_error
                )
        raise

    # A `Popen` failure here propagates as-is — nothing to catch, nothing to add. The
    # mutation already landed and the state record already shows it (inspectable, not
    # lost); the absence of `<action_id>.watchdog_pid` after this raises is itself the
    # visible signal that no revert was ever scheduled.
    watchdog_pid = _spawn_watchdog(action.action_id, deadline_epoch, state_dir)

    _write_text_atomic(_pid_path(state_dir, action.action_id), str(watchdog_pid))


def revert_action(action_id: str, *, state_dir: Path) -> None:
    """Undo ``action_id``'s effect, restoring whatever ``target_path`` held before it
    ran.

    Idempotent: a second call on an already-reverted action is a no-op, not an error and
    not a second application. Raises :class:`ValueError` naming ``action_id`` if it was
    never executed — reverting an unknown action must fail loudly, never silently
    succeed.

    **Status moves ``"executed"`` → ``"reverting"`` → ``"reverted"``, and the ordering is
    load-bearing** (`silent-failure-hunter`, task 10's review): the intent is recorded
    *before* the target is mutated, mirroring :func:`execute_action`. Writing the
    completion first and mutating after would leave the reverse lie — a record claiming
    the world was restored when it was not — so instead a crash or a failed final write
    leaves ``"reverting"``, which says exactly what is true: a revert was attempted and
    its completion was not recorded. That state is safely retryable, because restoring a
    known ``previous_value`` is idempotent (the same bytes written twice, or
    ``unlink(missing_ok=True)`` twice, yield the same world), so the next call — a later
    watchdog, an operator tool — completes it. The early return therefore fires on
    ``"reverted"`` only, never on ``"reverting"``.

    **A second, compare-before-write check closes a narrower window than that early
    return** (`D-S42`): a caller that read the record *before* a concurrent call to this
    function finished holds a stale ``"reverting"`` snapshot even after that concurrent
    call has gone on to write ``"reverted"``. Without re-checking, that stale caller would
    write ``"reverting"`` back over the now-completed record — a *permanent* regression if
    the stale caller then dies before its own completion write, since nothing left in the
    codebase would advance a record stuck at ``"reverting"`` again.

    **A per-`action_id` OS-level advisory lock makes that re-read-and-write atomic with
    respect to every other concurrent caller** (`D-S44`, narrowed by `D-S45`): held only
    across the compare-before-write re-read immediately below and the ``"reverting"``
    write that follows it — not across this function's entire body. The entry-check read
    above, the target mutation, and the final ``"reverted"`` write all stay unlocked,
    exactly as before `D-S45`; locking them too would make two genuinely overlapping calls
    to this function structurally impossible, which is precisely the conflict `D-S45`
    corrects. The bail condition inside the lock is unchanged: bail on ``"reverted"``
    only, never on ``"reverting"`` — a genuinely stuck ``"reverting"`` record (`D-S36`)
    must remain completable by a later, non-concurrent call.
    """
    state_path = _state_path(state_dir, action_id)
    if not state_path.exists():
        raise ValueError(f"action {action_id!r} was never executed; nothing to revert")

    state = _read_state(state_path)
    if state["status"] == "reverted":
        # Not a bare early return any more: if this process died between the terminal
        # write and the release below, nothing else would ever repair the leaked claim,
        # and the state directory would permanently claim a key nobody holds. The release
        # is compare-guarded and idempotent, so retrying it here is free and self-healing.
        _release_claim_of(state, state_dir, action_id)
        return

    target_path = Path(state["target_path"]) if state["target_path"] else None
    previous_value = state["previous_value"]

    with _locked(_action_file(state_dir, action_id, ".lock")):
        if _read_state(state_path)["status"] == "reverted":
            # Same leaked-claim window as the outer branch above, reached by the
            # concurrent path instead of the sequential-retry one: the winner of this
            # lock could have died between its own "reverted" write (line 641-643) and
            # its release call (line 645), and this loser is the only caller left that
            # will ever observe the terminal state. `state`'s `idempotency_key` is
            # immutable once execution recorded it, so the outer, stale copy is still
            # the right value to release with.
            _release_claim_of(state, state_dir, action_id)
            return
        state["status"] = "reverting"
        _write_state(state_path, state)

    undo_urls = state.get("undo_urls")
    if undo_urls:
        for url in undo_urls:
            _http_delete(url)
    elif previous_value is None:
        assert target_path is not None
        target_path.unlink(missing_ok=True)
    else:
        assert target_path is not None
        target_path.write_text(previous_value, encoding="utf-8")

    state["status"] = "reverted"
    state["reverted_at_epoch"] = time.time()
    _write_state(state_path, state)

    _release_claim_of(state, state_dir, action_id)
