"""
Alerting integrations for QuerySense.

Provides Slack, PagerDuty, and email notification channels for plan
regression events detected by `querysense watch` or CI/CD pipelines.

Usage:
    from querysense.alerting import SlackAlert, PagerDutyAlert, AlertDispatcher

    dispatcher = AlertDispatcher()
    dispatcher.add_channel(SlackAlert(webhook_url="https://hooks.slack.com/..."))
    dispatcher.add_channel(PagerDutyAlert(routing_key="..."))

    await dispatcher.send(regression_verdict)
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.error import URLError
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from querysense.baseline import RegressionVerdict

logger = logging.getLogger(__name__)


# ── Alert Channel Protocol ─────────────────────────────────────────────


@dataclass(frozen=True)
class AlertPayload:
    """Normalized alert payload sent to all channels."""

    query_id: str
    severity: str  # "critical", "high", "medium", "low"
    danger_score: int
    summary: str
    structural_changes: list[str] = field(default_factory=list)
    cost_change: str = ""
    plausible_causes: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "querysense watch"
    hostname: str = ""

    @classmethod
    def from_verdict(cls, verdict: "RegressionVerdict", hostname: str = "") -> "AlertPayload":
        """Create an AlertPayload from a RegressionVerdict."""
        return cls(
            query_id=verdict.query_id,
            severity=verdict.severity.value,
            danger_score=verdict.danger_score,
            summary=verdict.rationale or f"Plan regression on {verdict.query_id}",
            structural_changes=list(verdict.structural_changes),
            cost_change=verdict.cost_change_summary,
            plausible_causes=list(verdict.plausible_causes),
            recommended_actions=list(verdict.recommended_actions),
            hostname=hostname,
        )


class AlertChannel(ABC):
    """Base class for alert channels."""

    @abstractmethod
    def send(self, payload: AlertPayload) -> bool:
        """
        Send an alert. Returns True if successful.

        Implementations should not raise exceptions — log and return False.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this channel."""
        ...


# ── Slack ──────────────────────────────────────────────────────────────


class SlackAlert(AlertChannel):
    """Send alerts to Slack via incoming webhook."""

    def __init__(self, webhook_url: str, channel: str | None = None) -> None:
        self.webhook_url = webhook_url
        self.channel = channel

    @property
    def name(self) -> str:
        return "Slack"

    def send(self, payload: AlertPayload) -> bool:
        severity_emoji = {
            "critical": ":red_circle:",
            "high": ":large_orange_circle:",
            "medium": ":large_yellow_circle:",
            "low": ":white_circle:",
        }
        emoji = severity_emoji.get(payload.severity, ":grey_question:")

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Plan Regression: {payload.query_id}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{payload.severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Danger Score:*\n{payload.danger_score}/100"},
                    {"type": "mrkdwn", "text": f"*Source:*\n{payload.source}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{payload.timestamp[:19]}"},
                ],
            },
        ]

        if payload.summary:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{payload.summary[:500]}"},
            })

        if payload.structural_changes:
            changes_text = "\n".join(f"• {c}" for c in payload.structural_changes[:5])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Changes:*\n{changes_text}"},
            })

        if payload.cost_change:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Cost:* {payload.cost_change}"},
            })

        if payload.recommended_actions:
            actions_text = "\n".join(f"• {a}" for a in payload.recommended_actions[:3])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Actions:*\n{actions_text}"},
            })

        blocks.append({"type": "divider"})

        slack_payload: dict[str, Any] = {"blocks": blocks}
        if self.channel:
            slack_payload["channel"] = self.channel

        return self._post(slack_payload)

    def _post(self, data: dict[str, Any]) -> bool:
        try:
            body = json.dumps(data).encode("utf-8")
            req = Request(
                self.webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (URLError, OSError) as e:
            logger.error("Slack alert failed: %s", e)
            return False


# ── PagerDuty ──────────────────────────────────────────────────────────


class PagerDutyAlert(AlertChannel):
    """Send alerts to PagerDuty via Events API v2."""

    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str) -> None:
        self.routing_key = routing_key

    @property
    def name(self) -> str:
        return "PagerDuty"

    def send(self, payload: AlertPayload) -> bool:
        severity_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
        }

        pd_payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": f"querysense-{payload.query_id}-{payload.timestamp[:10]}",
            "payload": {
                "summary": (
                    f"[QuerySense] {payload.severity.upper()} plan regression "
                    f"on {payload.query_id} (danger: {payload.danger_score}/100)"
                ),
                "source": payload.hostname or "querysense",
                "severity": severity_map.get(payload.severity, "warning"),
                "component": "database",
                "group": "query-performance",
                "class": "plan-regression",
                "custom_details": {
                    "query_id": payload.query_id,
                    "danger_score": payload.danger_score,
                    "structural_changes": payload.structural_changes,
                    "cost_change": payload.cost_change,
                    "plausible_causes": payload.plausible_causes,
                    "recommended_actions": payload.recommended_actions,
                },
            },
        }

        try:
            body = json.dumps(pd_payload).encode("utf-8")
            req = Request(
                self.EVENTS_URL,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status in (200, 202)
        except (URLError, OSError) as e:
            logger.error("PagerDuty alert failed: %s", e)
            return False


# ── Email (SMTP) ───────────────────────────────────────────────────────


class EmailAlert(AlertChannel):
    """Send alerts via SMTP email."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        from_addr: str = "querysense@localhost",
        to_addrs: list[str] | None = None,
        use_tls: bool = True,
    ) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs or []
        self.use_tls = use_tls

    @property
    def name(self) -> str:
        return "Email"

    def send(self, payload: AlertPayload) -> bool:
        if not self.to_addrs:
            logger.warning("Email alert: no recipients configured")
            return False

        try:
            import smtplib
            from email.mime.text import MIMEText

            subject = (
                f"[QuerySense] {payload.severity.upper()} regression: {payload.query_id}"
            )

            body_lines = [
                f"Plan Regression Detected",
                f"========================",
                f"",
                f"Query: {payload.query_id}",
                f"Severity: {payload.severity.upper()}",
                f"Danger Score: {payload.danger_score}/100",
                f"Time: {payload.timestamp}",
                f"Source: {payload.source}",
                f"",
                f"Summary: {payload.summary}",
            ]

            if payload.cost_change:
                body_lines.append(f"Cost: {payload.cost_change}")

            if payload.structural_changes:
                body_lines.append("")
                body_lines.append("Structural Changes:")
                for c in payload.structural_changes:
                    body_lines.append(f"  - {c}")

            if payload.recommended_actions:
                body_lines.append("")
                body_lines.append("Recommended Actions:")
                for a in payload.recommended_actions:
                    body_lines.append(f"  - {a}")

            body_lines.append("")
            body_lines.append("-- QuerySense (https://github.com/JosephAhn23/Query-Sense)")

            msg = MIMEText("\n".join(body_lines))
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_addrs)

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                if self.use_tls:
                    server.starttls()
                if self.username:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())

            return True
        except Exception as e:
            logger.error("Email alert failed: %s", e)
            return False


# ── Dispatcher ─────────────────────────────────────────────────────────


class AlertDispatcher:
    """
    Fan-out dispatcher that sends alerts to multiple channels.

    Channels are called sequentially; failures are logged but don't
    stop other channels from being attempted.
    """

    def __init__(self) -> None:
        self._channels: list[AlertChannel] = []

    def add_channel(self, channel: AlertChannel) -> None:
        """Register an alert channel."""
        self._channels.append(channel)
        logger.info("Registered alert channel: %s", channel.name)

    def send(self, payload: AlertPayload) -> dict[str, bool]:
        """
        Send alert to all channels.

        Returns:
            Dict mapping channel name to success boolean.
        """
        results: dict[str, bool] = {}
        for channel in self._channels:
            try:
                ok = channel.send(payload)
                results[channel.name] = ok
                if ok:
                    logger.info("Alert sent via %s for %s", channel.name, payload.query_id)
                else:
                    logger.warning("Alert failed via %s for %s", channel.name, payload.query_id)
            except Exception as e:
                logger.error("Alert channel %s raised: %s", channel.name, e)
                results[channel.name] = False
        return results

    def send_verdict(
        self, verdict: "RegressionVerdict", hostname: str = ""
    ) -> dict[str, bool]:
        """Convenience: send from a RegressionVerdict."""
        payload = AlertPayload.from_verdict(verdict, hostname=hostname)
        return self.send(payload)

    @property
    def channel_count(self) -> int:
        return len(self._channels)

    @property
    def channel_names(self) -> list[str]:
        return [c.name for c in self._channels]
