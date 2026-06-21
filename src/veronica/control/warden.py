"""Warden — the host-side reasoning agent that owns the policy lifecycle.

It is the only reasoning component: NL -> {primitive_id, params} (via translate),
the audit -> confirm -> enforce lifecycle, and observation -> NL summary. It
never enforces directly; every policy lands in audit, and only an explicit
`confirm` flips it to enforce. `panic` detaches everything.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from veronica.control.client import Activity, DaemonClient, Policy
from veronica.control.translate import LLM, translate


@dataclass(frozen=True)
class AuditReport:
    """Result of `enforce`: the audit-mode policy and its would-block summary."""

    policy_id: str
    primitive_id: str
    params: dict
    would_block: int
    confirm_hint: str


class Warden:
    def __init__(self, client: DaemonClient, llm: LLM) -> None:
        self.client = client
        self.llm = llm

    def enforce(self, nl: str) -> AuditReport:
        """Translate NL -> primitive, apply in audit, report would-block count."""
        primitives = self.client.list_primitives()
        primitive_id, params = translate(nl, primitives, self.llm)
        policy = self.client.apply_policy(primitive_id, params, "audit")
        return AuditReport(
            policy_id=policy.id,
            primitive_id=policy.primitive_id,
            params=policy.params,
            would_block=policy.audit_count,
            confirm_hint=f"confirm to enforce: veronica audit {policy.id} --confirm",
        )

    def confirm(self, policy_id: str) -> Policy:
        """Flip an audited policy from audit to enforce."""
        return self.client.set_policy_mode(policy_id, "enforce")

    def ask(self, app: str, question: str, window_secs: int = 30) -> str:
        """Summarize the app's recent activity into a natural-language answer."""
        activity = self.client.observe(app, window_secs)
        return self.llm.complete(_ASK_SYSTEM, _ask_prompt(app, question, activity))

    def panic(self) -> int:
        """Kill switch: detach every policy; return how many were cleared."""
        return self.client.kill_switch()["reverted"]


_ASK_SYSTEM = (
    "You summarize an application's recent kernel-sourced activity (files, "
    "network, exec, mounts) into a short, plain-language answer to the user's "
    "question. Be concrete; cite what you see."
)


def _ask_prompt(app: str, question: str, activity: Activity) -> str:
    return (
        f"Question: {question}\n\n"
        f"Recent activity for {app} (last {activity.window}s):\n"
        f"{json.dumps(_activity_dict(activity), indent=2)}"
    )


def _activity_dict(activity: Activity) -> dict:
    return {
        "files": [vars(e) for e in activity.files],
        "net": [vars(e) for e in activity.net],
        "execs": [vars(e) for e in activity.execs],
        "mounts": [vars(e) for e in activity.mounts],
    }
