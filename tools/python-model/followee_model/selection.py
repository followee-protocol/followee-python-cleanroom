"""Deterministic candidate selection with sticky root revocation
(Sections 8.2-8.4 and step 19 of Section 8.1).

Selection is a pure function of the candidate set, the recipient clock, and
the incoming sticky state; candidate arrival order never affects the winner
(Section 20.4).
"""

from dataclasses import dataclass
from typing import List, Optional

from .errors import ErrorCode, FolloweeError
from .record import AUTHORITY_ROOT, AUTHORITY_ROOT_REVOKED
from .verify import VerifiedRecord, verify_full_record


@dataclass
class CandidateOutcome:
    """Per-candidate classification, aligned with the input list."""

    envelope: bytes
    record: Optional[VerifiedRecord]  # None when verification failed
    error: Optional[ErrorCode]  # None only for the winner
    is_winner: bool


@dataclass
class SelectionResult:
    winner: Optional[VerifiedRecord]
    root_revoked: bool  # updated sticky authority state
    outcomes: List[CandidateOutcome]


def _beats(a: VerifiedRecord, b: VerifiedRecord) -> bool:
    """Section 8.3 ordering within one authority state: greater timestamp
    wins; at equal timestamps the lexicographically lower 32-byte body
    digest wins (unsigned bytes, left to right)."""
    if a.timestamp_ms != b.timestamp_ms:
        return a.timestamp_ms > b.timestamp_ms
    return a.body_digest < b.body_digest


def select_current(
    target: str,
    candidate_envelopes: List[bytes],
    now_ms: int,
    sticky_root_revoked: bool = False,
) -> SelectionResult:
    """Verify every candidate independently, apply sticky root revocation,
    and select the winning admissible record."""
    verified: List[Optional[VerifiedRecord]] = []
    errors: List[Optional[ErrorCode]] = []
    for envelope in candidate_envelopes:
        try:
            verified.append(verify_full_record(target, envelope, now_ms))
            errors.append(None)
        except FolloweeError as exc:
            verified.append(None)
            errors.append(exc.code)

    # Any signature-valid, descriptor-bound, non-premature RootRevoked record
    # activates sticky RootRevoked state (Section 8.2).  A stale RootRevoked
    # record still activates the transition; a premature one does not.
    root_revoked = sticky_root_revoked or any(
        rec is not None
        and rec.authority == AUTHORITY_ROOT_REVOKED
        and not rec.premature
        for rec in verified
    )
    applicable_authority = (
        AUTHORITY_ROOT_REVOKED if root_revoked else AUTHORITY_ROOT
    )

    winner: Optional[VerifiedRecord] = None
    for rec in verified:
        if rec is None or rec.premature:
            continue
        if rec.authority != applicable_authority:
            continue
        if winner is None or _beats(rec, winner):
            winner = rec

    outcomes: List[CandidateOutcome] = []
    winner_assigned = False
    for envelope, rec, error in zip(candidate_envelopes, verified, errors):
        if rec is None:
            outcomes.append(CandidateOutcome(envelope, None, error, False))
            continue
        if rec.premature:
            outcomes.append(
                CandidateOutcome(envelope, rec, ErrorCode.PREMATURE, False)
            )
            continue
        if root_revoked and rec.authority == AUTHORITY_ROOT:
            outcomes.append(
                CandidateOutcome(envelope, rec, ErrorCode.ROOT_REVOKED, False)
            )
            continue
        if winner is not None and rec.body_digest == winner.body_digest:
            if not winner_assigned:
                outcomes.append(CandidateOutcome(envelope, rec, None, True))
                winner_assigned = True
            else:
                # Exact body-digest match is a duplicate even if envelope
                # bytes differ (Section 8.4).
                outcomes.append(
                    CandidateOutcome(envelope, rec, ErrorCode.DUPLICATE, False)
                )
            continue
        outcomes.append(
            CandidateOutcome(envelope, rec, ErrorCode.LOSING_RECORD, False)
        )

    return SelectionResult(
        winner=winner, root_revoked=root_revoked, outcomes=outcomes
    )
