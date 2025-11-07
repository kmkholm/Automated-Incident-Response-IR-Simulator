
#!/usr/bin/env python3
"""
Playbook-Driven Automated Incident Response (IR) System - Tkinter Simulation Suite
Author: Dr. Mohammed Tawfik <kmkhol01@gmail.com>
-------------------------------------------------------------------------------
This single-file application demonstrates an end-to-end design and simulation
of a playbook-driven automated Incident Response system with:
  * Normalized alert contract
  * SOAR-like playbook orchestration (enrichment -> decision -> action)
  * Mock connectors (IdP, EDR, Email, Cloud)
  * Case management & audit trails
  * Human-in-the-loop approvals, kill switch, dry-run, RBAC roles (simulated)
  * Metrics: MTTD, MTTR, coverage by ATT&CK tactics, false-positive rate, etc.
  * A full GUI using Tkinter + ttk.Notebook
  * Embedded matplotlib dashboards updated in real time
  * A traffic simulator generating synthetic alerts mapped to MITRE ATT&CK
  * Sandbox-safe: no destructive actions, purely simulated

NOTE:
  - This demo emphasizes architecture & UX for training or POC purposes.
  - All connectors are mock implementations with deterministic/random outcomes.
  - Playbooks are defined in JSON with a mini-DSL for decisions.
  - The code is intentionally verbose with extensive comments to exceed 2000 lines
    per user request, and to serve as a teaching/reference resource.
"""


import sys
import os
import threading
import queue
import math
import uuid
import traceback
import functools
import itertools
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable, Tuple

# Tkinter & ttk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Matplotlib embedding
import matplotlib
matplotlib.use("TkAgg")  # backend set before importing pyplot; we'll switch per-canvas
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# For JSON persistence
import json

# Time utils
from time import perf_counter
from datetime import datetime, timezone


APP_NAME = "IR Playbook Simulator"
APP_VERSION = "1.0.0"
DEFAULT_FONT = ("Segoe UI", 10)
MONO_FONT = ("Consolas", 10)

# Severity mapping
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Default config persisted to disk (user's home by default if running locally)
DEFAULT_CONFIG = {
    "dry_run": True,
    "kill_switch": False,
    "require_approval_for_destructive": True,
    "worker_threads": 3,
    "max_queue": 1000,
    "mttr_target_minutes": 60,
    "mttd_target_minutes": 10,
    "random_seed": 1337,
    "log_level": "INFO",
    "auto_open_cases": True,
    "save_path": "ir_sim_state.json",
}

# Helper: unified time
def utcnow() -> str:
    # Robust UTC timestamp without relying on external aliases
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

def short_uuid() -> str:
    return str(uuid.uuid4())[:8]


@dataclass
class Alert:
    id: str
    source: str
    rule: Dict[str, Any]
    entity: Dict[str, Any]
    evidence: Dict[str, Any]
    ioc: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    ts_created: float = field(default_factory=lambda: time.time())
    acknowledged: bool = False
    status: str = "new"  # new -> in_progress -> contained|benign|escalated|failed
    playbook: Optional[str] = None
    playbook_run_id: Optional[str] = None
    case_id: Optional[str] = None

@dataclass
class Case:
    id: str
    title: str
    severity: str
    created: str
    updated: str
    status: str = "open"  # open -> contained|closed|failed
    owner: Optional[str] = None
    summary: str = ""
    alerts: List[str] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    audit_log: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class AuditEntry:
    timestamp: str
    playbook_run_id: str
    step: str
    result: str
    details: Dict[str, Any] = field(default_factory=dict)


class EventBus:
    """
    Thread-safe pub/sub for UI updates and orchestration events.
    """
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}
        self.lock = threading.Lock()

    def subscribe(self, topic: str, callback: Callable):
        with self.lock:
            self.subscribers.setdefault(topic, []).append(callback)

    def publish(self, topic: str, payload: Any = None):
        with self.lock:
            listeners = list(self.subscribers.get(topic, []))
        for cb in listeners:
            try:
                cb(payload)
            except Exception as e:
                print(f"[EventBus] subscriber error on {topic}: {e}", file=sys.stderr)
                traceback.print_exc()


class RingLogger:
    def __init__(self, capacity: int = 10000):
        self.capacity = capacity
        self.buffer: List[str] = []
        self.lock = threading.Lock()

    def log(self, level: str, msg: str):
        line = f"{utcnow()} [{level}] {msg}"
        with self.lock:
            self.buffer.append(line)
            if len(self.buffer) > self.capacity:
                self.buffer = self.buffer[-self.capacity:]
        print(line)

    def tail(self, n: int = 500) -> List[str]:
        with self.lock:
            return self.buffer[-n:]


class MetricsStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.alerts_total = 0
        self.alerts_by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        self.auto_resolved = 0
        self.escalated = 0
        self.false_positive = 0
        self.playbook_runs = 0
        self.queue_depth_samples: List[Tuple[float, int]] = []  # (time, depth)
        self.mttr_samples: List[float] = []  # seconds
        self.mttd_samples: List[float] = []  # seconds
        self.coverage_by_tactic: Dict[str, int] = {}
        self.case_count_open = 0
        self.case_count_closed = 0

    def record_alert(self, severity: str):
        with self.lock:
            self.alerts_total += 1
            self.alerts_by_severity[severity] = self.alerts_by_severity.get(severity, 0) + 1

    def record_playbook_run(self, tactics: List[str]):
        with self.lock:
            self.playbook_runs += 1
            for t in tactics:
                self.coverage_by_tactic[t] = self.coverage_by_tactic.get(t, 0) + 1

    def record_resolution(self, status: str, detected_at: float, contained_at: float):
        with self.lock:
            if status == "contained":
                self.auto_resolved += 1
            elif status == "escalated":
                self.escalated += 1
            elif status == "benign":
                self.false_positive += 1
            # MTTR assumes detection to containment/closure
            self.mttr_samples.append(float(max(0.01, contained_at - detected_at)))

    def record_detection(self, alerted_at: float, event_first_seen: float):
        with self.lock:
            self.mttd_samples.append(float(max(0.01, alerted_at - event_first_seen)))

    def sample_queue_depth(self, ts: float, depth: int):
        with self.lock:
            self.queue_depth_samples.append((ts, depth))
            if len(self.queue_depth_samples) > 2000:
                self.queue_depth_samples = self.queue_depth_samples[-2000:]

    def cases_open(self, n: int):
        with self.lock:
            self.case_count_open = n

    def cases_closed(self, n: int):
        with self.lock:
            self.case_count_closed = n

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "alerts_total": self.alerts_total,
                "alerts_by_severity": dict(self.alerts_by_severity),
                "auto_resolved": self.auto_resolved,
                "escalated": self.escalated,
                "false_positive": self.false_positive,
                "playbook_runs": self.playbook_runs,
                "coverage_by_tactic": dict(self.coverage_by_tactic),
                "queue_depth_samples": list(self.queue_depth_samples[-300:]),
                "mttr_samples": list(self.mttr_samples[-300:]),
                "mttd_samples": list(self.mttd_samples[-300:]),
                "case_count_open": self.case_count_open,
                "case_count_closed": self.case_count_closed,
            }


class CaseManager:
    def __init__(self, bus: EventBus, log: RingLogger, metrics: MetricsStore):
        self.bus = bus
        self.log = log
        self.metrics = metrics
        self.cases: Dict[str, Case] = {}
        self.lock = threading.Lock()

    def open_case(self, title: str, severity: str, initial_alert: Optional[Alert] = None) -> Case:
        cid = f"CASE-{short_uuid()}"
        now = utcnow()
        case = Case(id=cid, title=title, severity=severity, created=now, updated=now)
        if initial_alert:
            case.alerts.append(initial_alert.id)
        with self.lock:
            self.cases[cid] = case
            self.metrics.cases_open(len([c for c in self.cases.values() if c.status == "open"]))
            self.metrics.cases_closed(len([c for c in self.cases.values() if c.status != "open"]))
        self.log.log("INFO", f"Opened case {cid} for {title} ({severity})")
        self.bus.publish("case_opened", case)
        return case

    def append_alert(self, case_id: str, alert_id: str):
        with self.lock:
            case = self.cases.get(case_id)
            if not case: return
            case.alerts.append(alert_id)
            case.updated = utcnow()
        self.bus.publish("case_updated", self.cases[case_id])

    def add_audit(self, case_id: str, entry: AuditEntry):
        with self.lock:
            case = self.cases.get(case_id)
            if not case: return
            case.audit_log.append(entry.__dict__)
            case.updated = utcnow()
        self.bus.publish("case_updated", self.cases[case_id])

    def set_status(self, case_id: str, status: str, summary: Optional[str] = None):
        with self.lock:
            case = self.cases.get(case_id)
            if not case: return
            case.status = status
            if summary:
                case.summary = summary
            case.updated = utcnow()
            self.metrics.cases_open(len([c for c in self.cases.values() if c.status == "open"]))
            self.metrics.cases_closed(len([c for c in self.cases.values() if c.status != "open"]))
        self.bus.publish("case_updated", self.cases[case_id])

    def list_cases(self) -> List[Case]:
        with self.lock:
            return list(self.cases.values())

    def to_json(self) -> Dict[str, Any]:
        with self.lock:
            return {cid: c.__dict__ for cid, c in self.cases.items()}

    def load_json(self, data: Dict[str, Any]):
        with self.lock:
            self.cases = {cid: Case(**c) for cid, c in data.items()}
        self.metrics.cases_open(len([c for c in self.cases.values() if c.status == "open"]))
        self.metrics.cases_closed(len([c for c in self.cases.values() if c.status != "open"]))
        self.bus.publish("cases_loaded", None)


class SafeExpr:
    """
    Extremely small expression evaluator for playbook decisions.
    Allowed tokens: numbers, booleans, comparisons, and functions we register.
    """
    def __init__(self):
        self.funcs = {
            "score": lambda x: float(x) if isinstance(x, (int, float, str)) and str(x).replace('.','',1).isdigit() else 0.0,
            "gte": lambda a,b: float(a) >= float(b),
            "lte": lambda a,b: float(a) <= float(b),
            "gt": lambda a,b: float(a) > float(b),
            "lt": lambda a,b: float(a) < float(b),
            "eq": lambda a,b: a == b,
            "contains": lambda a,b: (b in a) if hasattr(a, "__contains__") else False,
            "anytrue": lambda *args: any(bool(x) for x in args),
            "alltrue": lambda *args: all(bool(x) for x in args),
        }

    def eval(self, expression: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
        """
        expression example:
        { "fn": "gte", "args": [ {"fn":"score","args":["sender_rep"]}, 70 ] }
        ctx example:
        { "sender_rep": 65, "url_risk": 80 }
        """
        if isinstance(expression, (int, float, str, bool)):
            return expression
        if not isinstance(expression, dict) or "fn" not in expression:
            return False
        fn = expression.get("fn")
        args = expression.get("args", [])
        evaled_args = []
        for a in args:
            if isinstance(a, dict):
                evaled_args.append(self.eval(a, ctx))
            elif isinstance(a, str):
                # interpret as variable if present
                evaled_args.append(ctx.get(a, a))
            else:
                evaled_args.append(a)
        f = self.funcs.get(fn)
        if not f:
            return False
        try:
            return f(*evaled_args)
        except Exception:
            return False


class PlaybookRegistry:
    def __init__(self):
        # Simple JSON-serializable playbook DSL
        # steps: list of operations: enrich/decision/action/case_update/notify/approval
        self.playbooks: Dict[str, Dict[str, Any]] = {}

        # Seed some defaults
        self.register(self._example_phishing())
        self.register(self._example_impossible_travel())
        self.register(self._example_malware_on_endpoint())
        self.register(self._example_privilege_escalation())
        self.register(self._example_ransomware_burst())
        self.register(self._example_cloud_key_leak())

    def register(self, pb: Dict[str, Any]):
        self.playbooks[pb["name"]] = pb

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        return self.playbooks.get(name)

    def all(self) -> List[Dict[str, Any]]:
        return list(self.playbooks.values())

    def choose_for_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        # naive mapping by rule_id prefixes
        for pb in self.playbooks.values():
            triggers = pb.get("triggers", [])
            for t in triggers:
                if t.get("rule_id") == rule_id or t.get("tag") in rule_id:
                    return pb
        return None

    def _example_phishing(self) -> Dict[str, Any]:
        return {
            "name": "Phishing_Triage_v1",
            "version": "1.2.0",
            "tactics": ["Initial Access", "Credential Access"],
            "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
            "steps": [
                {"enrich": {"sender_reputation": True, "url_sandbox": True, "vt_hash": True}},
                {"decision": {
                    "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 70]},
                    "on_true": "quarantine_email",
                    "on_false": "close_benign"
                }},
                {"action": "quarantine_email"},
                {"notify": {"channel": "user", "template": "phish-education-v1"}},
                {"case_update": {"status": "contained", "summary": "Email quarantined; awareness sent."}}
            ]
        }

    def _example_impossible_travel(self) -> Dict[str, Any]:
        return {
            "name": "Impossible_Travel_v1",
            "version": "1.0.0",
            "tactics": ["Initial Access"],
            "triggers": [{"rule_id": "R-1029", "tag": "impossible_travel"}],
            "steps": [
                {"enrich": {"geoip": True, "user_risk": True}},
                {"decision": {
                    "expression": {"fn":"gte","args":[{"fn":"score","args":["user_risk"]}, 60]},
                    "on_true": "revoke_sessions",
                    "on_false": "note_and_close"
                }},
                {"approval": {"required": True, "reason": "Invalidate active sessions"}},
                {"action": "revoke_sessions"},
                {"action": "force_mfa_reset"},
                {"case_update": {"status": "contained", "summary": "Sessions revoked; MFA reset enforced."}}
            ]
        }

    def _example_malware_on_endpoint(self) -> Dict[str, Any]:
        return {
            "name": "Malware_On_Endpoint_v1",
            "version": "1.1.0",
            "tactics": ["Execution", "Persistence", "Defense Evasion"],
            "triggers": [{"rule_id": "R-3100", "tag": "malware"}],
            "steps": [
                {"enrich": {"vt_hash": True, "edr_context": True}},
                {"decision": {
                    "expression": {"fn":"gte","args":[{"fn":"score","args":["malware_risk"]}, 80]},
                    "on_true": "isolate_host",
                    "on_false": "monitor_only"
                }},
                {"approval": {"required": True, "reason": "Isolate endpoint"}},
                {"action": "isolate_host"},
                {"action": "pull_triage_package"},
                {"case_update": {"status": "contained", "summary": "Host isolated; triage package collected."}}
            ]
        }

    def _example_privilege_escalation(self) -> Dict[str, Any]:
        return {
            "name": "Privilege_Escalation_v1",
            "version": "1.0.0",
            "tactics": ["Privilege Escalation", "Defense Evasion"],
            "triggers": [{"rule_id": "R-4010", "tag": "priv_esc"}],
            "steps": [
                {"enrich": {"iam_context": True, "change_history": True}},
                {"decision": {
                    "expression": {"fn":"gte","args":[{"fn":"score","args":["iam_risk"]}, 75]},
                    "on_true": "revoke_admin_rights",
                    "on_false": "document_and_close"
                }},
                {"action": "revoke_admin_rights"},
                {"action": "rotate_keys"},
                {"case_update": {"status": "contained", "summary": "Admin rights revoked; keys rotated."}}
            ]
        }

    def _example_ransomware_burst(self) -> Dict[str, Any]:
        return {
            "name": "Ransomware_Burst_v1",
            "version": "1.0.0",
            "tactics": ["Impact", "Command and Control"],
            "triggers": [{"rule_id": "R-9001", "tag": "ransomware"}],
            "steps": [
                {"enrich": {"edr_context": True, "network_flows": True}},
                {"approval": {"required": True, "reason": "Network-wide isolation"}},
                {"action": "isolate_host"},
                {"action": "block_c2_iocs"},
                {"action": "snapshot_host"},
                {"case_update": {"status": "contained", "summary": "Host isolated; C2 blocked; snapshot taken."}}
            ]
        }

    def _example_cloud_key_leak(self) -> Dict[str, Any]:
        return {
            "name": "Cloud_Access_Key_Leak_v1",
            "version": "1.0.0",
            "tactics": ["Credential Access", "Exfiltration"],
            "triggers": [{"rule_id": "R-7007", "tag": "key_leak"}],
            "steps": [
                {"enrich": {"cloud_context": True}},
                {"action": "revoke_cloud_keys"},
                {"action": "apply_block_policy"},
                {"case_update": {"status": "contained", "summary": "Leaked keys revoked; block policy applied."}}
            ]
        }


class IdPConnector:
    def __init__(self, log: RingLogger):
        self.log = log

    def revoke_sessions(self, user: str) -> bool:
        self.log.log("INFO", f"[IdP] Revoking sessions for {user}")
        return True

    def force_mfa_reset(self, user: str) -> bool:
        self.log.log("INFO", f"[IdP] Forcing MFA reset for {user}")
        return True

    def revoke_admin_rights(self, user: str) -> bool:
        self.log.log("INFO", f"[IdP] Revoking admin rights for {user}")
        return True

    def rotate_keys(self, user: str) -> bool:
        self.log.log("INFO", f"[IdP] Rotating keys for {user}")
        return True

class EDRConnector:
    def __init__(self, log: RingLogger):
        self.log = log

    def isolate_host(self, host: str) -> bool:
        self.log.log("INFO", f"[EDR] Isolating host {host}")
        return True

    def pull_triage_package(self, host: str) -> bool:
        self.log.log("INFO", f"[EDR] Pulling triage package from {host}")
        return True

    def snapshot_host(self, host: str) -> bool:
        self.log.log("INFO", f"[EDR] Snapshotting host {host}")
        return True

class EmailConnector:
    def __init__(self, log: RingLogger):
        self.log = log

    def quarantine_email(self, entity: Dict[str, Any]) -> bool:
        self.log.log("INFO", f"[Email] Quarantining email for {entity.get('principal')}")
        return True

    def send_user_notify(self, entity: Dict[str, Any], template: str):
        self.log.log("INFO", f"[Email] Notifying {entity.get('principal')} using template {template}")

class CloudConnector:
    def __init__(self, log: RingLogger):
        self.log = log

    def revoke_token(self, principal: str) -> bool:
        self.log.log("INFO", f"[Cloud] Revoking tokens for {principal}")
        return True

    def revoke_cloud_keys(self, principal: str) -> bool:
        self.log.log("INFO", f"[Cloud] Revoking cloud access keys for {principal}")
        return True

    def apply_block_policy(self, resource: str = "*") -> bool:
        self.log.log("INFO", f"[Cloud] Applying block policy to {resource}")
        return True

    def block_c2_iocs(self, iocs: List[str]) -> bool:
        self.log.log("INFO", f"[Cloud] Blocking C2 IoCs: {', '.join(iocs[:5])}{'...' if len(iocs) > 5 else ''}")
        return True


class Orchestrator:
    def __init__(self, bus: EventBus, log: RingLogger, metrics: MetricsStore, cases: CaseManager, playbooks: PlaybookRegistry, config: Dict[str, Any]):
        self.bus = bus
        self.log = log
        self.metrics = metrics
        self.cases = cases
        self.playbooks = playbooks
        self.config = dict(DEFAULT_CONFIG)
        self.config.update(config or {})
        self.queue: "queue.Queue[Alert]" = queue.Queue(maxsize=self.config.get("max_queue", 1000))
        self.workers: List[threading.Thread] = []
        self.running = False
        self.expr = SafeExpr()

        # Connectors
        self.idp = IdPConnector(log)
        self.edr = EDRConnector(log)
        self.email = EmailConnector(log)
        self.cloud = CloudConnector(log)

    def start(self):
        if self.running:
            return
        self.running = True
        n = self.config.get("worker_threads", 3)
        for i in range(n):
            t = threading.Thread(target=self._worker, name=f"Worker-{i+1}", daemon=True)
            t.start()
            self.workers.append(t)
        self.log.log("INFO", f"Orchestrator started with {n} workers")
        self.bus.publish("orch_started", None)

    def stop(self):
        self.running = False
        self.log.log("INFO", "Orchestrator stopping...")
        self.bus.publish("orch_stopping", None)

    def submit_alert(self, alert: Alert):
        try:
            self.queue.put_nowait(alert)
            self.metrics.record_alert(alert.rule.get("severity", "low"))
            self.bus.publish("alert_enqueued", alert)
        except queue.Full:
            self.log.log("ERROR", "Queue is full. Dropping alert.")
            self.bus.publish("alert_dropped", alert)

    def _worker(self):
        while self.running:
            try:
                alert = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._process_alert(alert)
            except Exception as e:
                self.log.log("ERROR", f"Error processing alert {alert.id}: {e}")
                traceback.print_exc()
            finally:
                self.queue.task_done()

    def _process_alert(self, alert: Alert):
        if self.config.get("kill_switch", False):
            self.log.log("WARN", f"Kill-switch active; logging only for {alert.id}")
            self._log_audit(None, alert, "kill_switch", "active", {})
            return

        # Determine playbook
        pb = self.playbooks.choose_for_rule(alert.rule.get("id", ""))
        if not pb:
            # fallback by tag heuristics
            rid = alert.rule.get("id","")
            if "2001" in rid or "phish" in rid:
                pb = self.playbooks.get("Phishing_Triage_v1")
            elif "1029" in rid or "travel" in rid:
                pb = self.playbooks.get("Impossible_Travel_v1")
            elif "3100" in rid or "malware" in rid:
                pb = self.playbooks.get("Malware_On_Endpoint_v1")
            elif "4010" in rid or "priv" in rid:
                pb = self.playbooks.get("Privilege_Escalation_v1")
            elif "9001" in rid or "ransom" in rid:
                pb = self.playbooks.get("Ransomware_Burst_v1")
            elif "7007" in rid or "key" in rid:
                pb = self.playbooks.get("Cloud_Access_Key_Leak_v1")

        alert.playbook = pb["name"] if pb else None
        run_id = f"RUN-{short_uuid()}"
        alert.playbook_run_id = run_id
        detected_at = alert.ts_created
        first_seen = alert.evidence.get("first_seen", alert.ts_created - random.uniform(10,120))
        self.metrics.record_detection(alerted_at=detected_at, event_first_seen=first_seen)

        # Case handling
        case: Optional[Case] = None
        if self.config.get("auto_open_cases", True):
            title = f"{alert.rule.get('name')} - {alert.entity.get('principal') or alert.entity.get('host')}"
            case = self.cases.open_case(title, alert.rule.get("severity","low"), alert)
            alert.case_id = case.id

        # Execute steps
        tactics = pb.get("tactics", []) if pb else []
        self.metrics.record_playbook_run(tactics)
        self.bus.publish("playbook_started", {"alert": alert, "playbook": pb})

        status = "escalated"  # default if nothing handles it
        for step in (pb.get("steps", []) if pb else []):
            if not self.running:
                break
            k = list(step.keys())[0]
            v = step[k]
            if k == "enrich":
                ctx = self._do_enrich(alert, v)
                self._log_audit(case, alert, "enrich", "ok", ctx)
            elif k == "decision":
                ctx = self._context_for_decision(alert)
                res = self.expr.eval(v.get("expression", True), ctx)
                self._log_audit(case, alert, "decision", "true" if res else "false", {"ctx": ctx})
                next_action = v.get("on_true") if res else v.get("on_false")
                if next_action:
                    self._do_named_action(case, alert, next_action)
            elif k == "approval":
                if self.config.get("require_approval_for_destructive", True) and v.get("required", False):
                    approved = self._mock_approval(case, alert, v.get("reason", ""))
                    self._log_audit(case, alert, "approval", "approved" if approved else "rejected", {"reason": v.get("reason")})
                    if not approved:
                        status = "escalated"
                        break
            elif k == "action":
                self._do_named_action(case, alert, v)
            elif k == "notify":
                self.email.send_user_notify(alert.entity, v.get("template","generic"))
                self._log_audit(case, alert, "notify", "sent", {"template": v.get("template")})
            elif k == "case_update":
                s = v.get("status", "open")
                summary = v.get("summary","")
                if case:
                    self.cases.set_status(case.id, s, summary)
                status = s
            else:
                self._log_audit(case, alert, "unknown_step", "skipped", {"step": k})

        contained_at = time.time()
        self.metrics.record_resolution(status=status, detected_at=detected_at, contained_at=contained_at)
        alert.status = status
        self.bus.publish("playbook_finished", {"alert": alert, "status": status})

    def _context_for_decision(self, alert: Alert) -> Dict[str, Any]:
        # Gather values from evidence/raw to feed decision engine
        ctx = {}
        ctx.update(alert.evidence)
        ctx.update({k: v for k, v in alert.raw.items() if isinstance(v, (int, float, str, bool))})
        # Derive a simple risk_score if not present
        if "risk_score" not in ctx:
            seed = SEVERITY_ORDER.get(alert.rule.get("severity","low"), 0) * 20
            ctx["risk_score"] = min(100, seed + random.randint(5, 45))
        return ctx

    def _do_enrich(self, alert: Alert, spec: Dict[str, Any]) -> Dict[str, Any]:
        ctx = {}
        if spec.get("sender_reputation"):
            ctx["sender_rep"] = random.randint(0, 100)
            alert.raw["sender_rep"] = ctx["sender_rep"]
        if spec.get("url_sandbox"):
            ctx["url_risk"] = random.randint(0, 100)
            alert.raw["url_risk"] = ctx["url_risk"]
        if spec.get("vt_hash"):
            ctx["hash_malicious"] = random.choice([True, False, False])
            alert.raw["hash_malicious"] = ctx["hash_malicious"]
        if spec.get("geoip"):
            ctx["geo_distance_km"] = random.randint(100, 8000)
            alert.raw["geo_distance_km"] = ctx["geo_distance_km"]
        if spec.get("user_risk"):
            ctx["user_risk"] = random.randint(0, 100)
            alert.raw["user_risk"] = ctx["user_risk"]
        if spec.get("edr_context"):
            ctx["malware_risk"] = random.randint(0, 100)
            alert.raw["malware_risk"] = ctx["malware_risk"]
        if spec.get("network_flows"):
            ctx["beaconing_score"] = random.randint(0, 100)
            alert.raw["beaconing_score"] = ctx["beaconing_score"]
        if spec.get("iam_context"):
            ctx["iam_risk"] = random.randint(0, 100)
            alert.raw["iam_risk"] = ctx["iam_risk"]
        if spec.get("cloud_context"):
            ctx["cloud_context_ok"] = random.choice([True, False])
            alert.raw["cloud_context_ok"] = ctx["cloud_context_ok"]
        return ctx

    def _do_named_action(self, case: Optional[Case], alert: Alert, action_name: str):
        entity = alert.entity
        ok = True
        if action_name == "quarantine_email":
            if not self.config.get("dry_run", True):
                ok = self.email.quarantine_email(entity)
            self._log_audit(case, alert, "action", "quarantine_email" if ok else "failed", {})
        elif action_name == "revoke_sessions":
            if not self.config.get("dry_run", True):
                ok = self.idp.revoke_sessions(entity.get("principal",""))
            self._log_audit(case, alert, "action", "revoke_sessions" if ok else "failed", {})
        elif action_name == "force_mfa_reset":
            if not self.config.get("dry_run", True):
                ok = self.idp.force_mfa_reset(entity.get("principal",""))
            self._log_audit(case, alert, "action", "force_mfa_reset" if ok else "failed", {})
        elif action_name == "isolate_host":
            if not self.config.get("dry_run", True):
                ok = self.edr.isolate_host(entity.get("host",""))
            self._log_audit(case, alert, "action", "isolate_host" if ok else "failed", {})
        elif action_name == "pull_triage_package":
            if not self.config.get("dry_run", True):
                ok = self.edr.pull_triage_package(entity.get("host",""))
            self._log_audit(case, alert, "action", "pull_triage_package" if ok else "failed", {})
        elif action_name == "snapshot_host":
            if not self.config.get("dry_run", True):
                ok = self.edr.snapshot_host(entity.get("host",""))
            self._log_audit(case, alert, "action", "snapshot_host" if ok else "failed", {})
        elif action_name == "revoke_admin_rights":
            if not self.config.get("dry_run", True):
                ok = self.idp.revoke_admin_rights(entity.get("principal",""))
            self._log_audit(case, alert, "action", "revoke_admin_rights" if ok else "failed", {})
        elif action_name == "rotate_keys":
            if not self.config.get("dry_run", True):
                ok = self.idp.rotate_keys(entity.get("principal",""))
            self._log_audit(case, alert, "action", "rotate_keys" if ok else "failed", {})
        elif action_name == "block_c2_iocs":
            if not self.config.get("dry_run", True):
                ok = self.cloud.block_c2_iocs(alert.ioc)
            self._log_audit(case, alert, "action", "block_c2_iocs" if ok else "failed", {})
        elif action_name == "revoke_cloud_keys":
            if not self.config.get("dry_run", True):
                ok = self.cloud.revoke_cloud_keys(entity.get("principal",""))
            self._log_audit(case, alert, "action", "revoke_cloud_keys" if ok else "failed", {})
        elif action_name == "apply_block_policy":
            if not self.config.get("dry_run", True):
                ok = self.cloud.apply_block_policy("*")
            self._log_audit(case, alert, "action", "apply_block_policy" if ok else "failed", {})
        elif action_name in ("close_benign","note_and_close","monitor_only","document_and_close"):
            if case:
                self.cases.set_status(case.id, "closed", f"Closed by {action_name}.")
            self._log_audit(case, alert, "action", action_name, {})
        else:
            self._log_audit(case, alert, "action_unknown", action_name, {})

    def _mock_approval(self, case: Optional[Case], alert: Alert, reason: str) -> bool:
        # Simulate human approval based on severity
        sev = alert.rule.get("severity","low")
        idx = SEVERITY_ORDER.get(sev,0)
        approved = random.random() < (0.8 if idx >= 2 else 0.6)
        return approved

    def _log_audit(self, case: Optional[Case], alert: Alert, step: str, result: str, details: Dict[str, Any]):
        entry = AuditEntry(timestamp=utcnow(), playbook_run_id=alert.playbook_run_id or "-", step=step, result=result, details=details)
        if case:
            self.cases.add_audit(case.id, entry)
        self.bus.publish("audit", {"alert_id": alert.id, "entry": entry.__dict__})

    def queue_depth(self) -> int:
        return self.queue.qsize()


class Simulator:
    RULES = [
        {"id": "R-2001", "name": "Suspicious Email Indicators", "severity": "medium"},
        {"id": "R-1029", "name": "Impossible Travel", "severity": "high"},
        {"id": "R-3100", "name": "Malicious File Execution", "severity": "high"},
        {"id": "R-4010", "name": "Privilege Escalation Detected", "severity": "high"},
        {"id": "R-9001", "name": "Ransomware Behavior Burst", "severity": "critical"},
        {"id": "R-7007", "name": "Cloud Access Key Leak", "severity": "critical"},
    ]

    PRINCIPALS = ["alice@corp.com", "bob@corp.com", "carol@corp.com", "dave@corp.com", "eve@corp.com", "mallory@corp.com"]
    HOSTS = ["LAPTOP-101", "SRV-DB-1", "SRV-WEB-2", "LAPTOP-202", "SRV-API-3", "LAPTOP-303"]

    def __init__(self, orch: Orchestrator, bus: EventBus, log: RingLogger, metrics: MetricsStore, seed: int = 1337):
        self.orch = orch
        self.bus = bus
        self.log = log
        self.metrics = metrics
        self.seed = seed
        self.rng = random.Random(seed)
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.rate_per_minute = 12  # default
        self.jitter = 0.4

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, name="Simulator", daemon=True)
        self.thread.start()
        self.log.log("INFO", "Simulator started")

    def stop(self):
        self.running = False
        self.log.log("INFO", "Simulator stopping...")

    def set_rate(self, rpm: int):
        self.rate_per_minute = max(1, int(rpm))

    def _loop(self):
        while self.running:
            start = perf_counter()
            # Generate N alerts this minute, but sleep in between for smoothness
            pause = max(0.1, 60.0 / max(1, self.rate_per_minute))
            self._emit_one()
            # sample queue depth for metrics
            self.metrics.sample_queue_depth(time.time(), self.orch.queue_depth())
            # Sleep with jitter
            sl = pause * self.rng.uniform(1.0 - self.jitter, 1.0 + self.jitter)
            time.sleep(sl)

    def _emit_one(self):
        rule = self.rng.choice(self.RULES)
        principal = self.rng.choice(self.PRINCIPALS)
        host = self.rng.choice(self.HOSTS)

        alert = Alert(
            id=f"AL-{short_uuid()}",
            source="siem",
            rule=dict(rule),
            entity={"principal": principal, "host": host, "ip": f"203.0.113.{self.rng.randint(1,254)}"},
            evidence={
                "events": self.rng.randint(1, 30),
                "first_seen": time.time() - self.rng.uniform(5, 600)
            },
            ioc=[f"bad{i}.example.com" for i in range(self.rng.randint(1, 4))],
            raw={}
        )
        self.orch.submit_alert(alert)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1280x800")
        try:
            self.iconbitmap(default="")
        except Exception:
            pass
        self.style = ttk.Style(self)
        self.style.theme_use("default")
        self.option_add("*Font", DEFAULT_FONT)

        # Core services
        self.bus = EventBus()
        self.log = RingLogger(15000)
        self.metrics = MetricsStore()
        self.cases = CaseManager(self.bus, self.log, self.metrics)
        self.pb = PlaybookRegistry()
        self.config_store = dict(DEFAULT_CONFIG)
        self.orch = Orchestrator(self.bus, self.log, self.metrics, self.cases, self.pb, self.config_store)
        self.sim = Simulator(self.orch, self.bus, self.log, self.metrics, seed=self.config_store.get("random_seed",1337))

        # UI containers
        self._build_menu()
        self._build_toolbar()
        self._build_tabs()

        # Subscriptions
        self.bus.subscribe("alert_enqueued", self.on_alert_enqueued)
        self.bus.subscribe("playbook_started", self.on_playbook_started)
        self.bus.subscribe("playbook_finished", self.on_playbook_finished)
        self.bus.subscribe("audit", self.on_audit)
        self.bus.subscribe("case_opened", lambda _: self.refresh_cases())
        self.bus.subscribe("case_updated", lambda _: self.refresh_cases())

        # State
        self.alerts: Dict[str, Alert] = {}
        self._ui_queue = queue.Queue()
        self.after(150, self._drain_ui_queue)

        # Start orchestrator by default
        self.orch.start()

    # ---------- UI BUILDERS ----------
    def _build_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        filemenu = tk.Menu(menubar, tearoff=False)
        filemenu.add_command(label="Save State", command=self._save_state)
        filemenu.add_command(label="Load State", command=self._load_state)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=filemenu)

        runmenu = tk.Menu(menubar, tearoff=False)
        runmenu.add_command(label="Start Orchestrator", command=self.orch.start)
        runmenu.add_command(label="Stop Orchestrator", command=self.orch.stop)
        runmenu.add_separator()
        runmenu.add_command(label="Start Simulator", command=self.sim.start)
        runmenu.add_command(label="Stop Simulator", command=self.sim.stop)
        menubar.add_cascade(label="Run", menu=runmenu)

        helpmenu = tk.Menu(menubar, tearoff=False)
        helpmenu.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=helpmenu)

    def _build_toolbar(self):
        bar = ttk.Frame(self)
        bar.pack(side=tk.TOP, fill=tk.X)

        self.var_dry = tk.BooleanVar(value=self.config_store["dry_run"])
        self.var_kill = tk.BooleanVar(value=self.config_store["kill_switch"])
        self.var_approval = tk.BooleanVar(value=self.config_store["require_approval_for_destructive"])
        self.var_rate = tk.IntVar(value=self.sim.rate_per_minute)

        ttk.Checkbutton(bar, text="Dry-run", variable=self.var_dry, command=self._toggle_dry).pack(side=tk.LEFT, padx=6, pady=4)
        ttk.Checkbutton(bar, text="Kill-switch", variable=self.var_kill, command=self._toggle_kill).pack(side=tk.LEFT, padx=6, pady=4)
        ttk.Checkbutton(bar, text="Require Approval", variable=self.var_approval, command=self._toggle_approval).pack(side=tk.LEFT, padx=6, pady=4)

        ttk.Label(bar, text="Simulator RPM:").pack(side=tk.LEFT, padx=(18,4))
        ttk.Spinbox(bar, from_=1, to=240, textvariable=self.var_rate, width=5, command=self._change_rate).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Start Sim", command=self.sim.start).pack(side=tk.LEFT, padx=6)
        ttk.Button(bar, text="Stop Sim", command=self.sim.stop).pack(side=tk.LEFT, padx=6)

        ttk.Button(bar, text="Save", command=self._save_state).pack(side=tk.RIGHT, padx=6)
        ttk.Button(bar, text="Load", command=self._load_state).pack(side=tk.RIGHT, padx=6)

    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.tab_dashboard = DashboardTab(nb, self)
        self.tab_alerts = AlertsTab(nb, self)
        self.tab_playbooks = PlaybooksTab(nb, self)
        self.tab_cases = CasesTab(nb, self)
        self.tab_simulator = SimulatorTab(nb, self)
        self.tab_settings = SettingsTab(nb, self)
        self.tab_logs = LogsTab(nb, self)

        nb.add(self.tab_dashboard, text="Dashboard")
        nb.add(self.tab_alerts, text="Alerts")
        nb.add(self.tab_playbooks, text="Playbooks")
        nb.add(self.tab_cases, text="Cases")
        nb.add(self.tab_simulator, text="Simulator")
        nb.add(self.tab_settings, text="Settings")
        nb.add(self.tab_logs, text="Logs")

    # ---------- Event handlers (thread-safe via _ui_queue) ----------
    def on_alert_enqueued(self, alert: Alert):
        self.alerts[alert.id] = alert
        self._ui_queue.put(("alert_new", alert))

    def on_playbook_started(self, payload: Dict[str, Any]):
        alert = payload["alert"]
        self._ui_queue.put(("alert_update", alert))

    def on_playbook_finished(self, payload: Dict[str, Any]):
        alert = payload["alert"]
        self._ui_queue.put(("alert_update", alert))

    def on_audit(self, payload: Dict[str, Any]):
        self._ui_queue.put(("audit", payload))

    def _drain_ui_queue(self):
        try:
            while True:
                evt, data = self._ui_queue.get_nowait()
                if evt == "alert_new":
                    self.tab_alerts.add_alert_row(data)
                    self.tab_dashboard.refresh()
                elif evt == "alert_update":
                    self.tab_alerts.update_alert_row(data)
                    self.tab_dashboard.refresh()
                elif evt == "audit":
                    entry = data["entry"]
                    self.tab_logs.append(f"{entry['timestamp']} [{entry['step']}] {entry['result']} :: {json.dumps(entry['details'])}")
        except queue.Empty:
            pass
        finally:
            # reschedule
            self.after(250, self._drain_ui_queue)

    # ---------- Helpers ----------
    def refresh_cases(self):
        self.tab_cases.refresh()

    def _toggle_dry(self):
        self.config_store["dry_run"] = bool(self.var_dry.get())
        self.tab_logs.append(f"Dry-run set to {self.config_store['dry_run']}")

    def _toggle_kill(self):
        self.config_store["kill_switch"] = bool(self.var_kill.get())
        self.tab_logs.append(f"Kill-switch set to {self.config_store['kill_switch']}")

    def _toggle_approval(self):
        self.config_store["require_approval_for_destructive"] = bool(self.var_approval.get())
        self.tab_logs.append(f"Require approval set to {self.config_store['require_approval_for_destructive']}")

    def _change_rate(self):
        rpm = int(self.var_rate.get())
        self.sim.set_rate(rpm)
        self.tab_logs.append(f"Simulator RPM set to {rpm}")

    def _save_state(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")], initialfile="ir_sim_state.json")
        if not path: return
        data = {
            "config": self.config_store,
            "cases": self.cases.to_json(),
            "metrics": self.metrics.snapshot(),
            "playbooks": {pb["name"]: pb for pb in self.pb.all()},
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self.tab_logs.append(f"State saved to {path}")

    def _load_state(self):
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json")])
        if not path: return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cfg = data.get("config", {})
        self.config_store.update(cfg)
        self.var_dry.set(self.config_store.get("dry_run", True))
        self.var_kill.set(self.config_store.get("kill_switch", False))
        self.var_approval.set(self.config_store.get("require_approval_for_destructive", True))
        cases = data.get("cases", {})
        self.cases.load_json(cases)
        # Playbooks re-register (optional)
        pbs = data.get("playbooks", {})
        for name, pb in pbs.items():
            self.pb.register(pb)
        self.tab_playbooks.reload()
        self.tab_dashboard.refresh()
        self.tab_logs.append(f"State loaded from {path}")

    def _about(self):
        messagebox.showinfo("About", f"{APP_NAME} v{APP_VERSION}\nPlaybook-driven IR Simulator\n© 2025 Example Lab\nAuthor: Dr. Mohammed Tawfik <kmkhol01@gmail.com>")

# ---------- Dashboard Tab ----------
class DashboardTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app
        self._build()

    def _build(self):
        # Layout: top stats row, bottom charts grid
        top = ttk.Frame(self)
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=6)

        self.lbl_total = ttk.Label(top, text="Alerts: 0")
        self.lbl_total.pack(side=tk.LEFT, padx=10)

        self.lbl_playbooks = ttk.Label(top, text="Playbook Runs: 0")
        self.lbl_playbooks.pack(side=tk.LEFT, padx=10)

        self.lbl_cases = ttk.Label(top, text="Cases Open: 0 / Closed: 0")
        self.lbl_cases.pack(side=tk.LEFT, padx=10)

        self.lbl_auto = ttk.Label(top, text="Auto-Resolved: 0 | Escalated: 0 | Benign: 0")
        self.lbl_auto.pack(side=tk.LEFT, padx=10)

        # Charts
        grid = ttk.Frame(self)
        grid.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Chart A: Queue depth over time (line)
        self.fig_a = Figure(figsize=(4.6,2.8), dpi=100)
        self.ax_a = self.fig_a.add_subplot(111)
        self.ax_a.set_title("Queue depth over time")
        self.ax_a.set_xlabel("Samples")
        self.ax_a.set_ylabel("Depth")
        self.canvas_a = FigureCanvasTkAgg(self.fig_a, master=grid)
        self.canvas_a_widget = self.canvas_a.get_tk_widget()
        self.canvas_a_widget.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Chart B: Alerts by severity (bar)
        self.fig_b = Figure(figsize=(4.6,2.8), dpi=100)
        self.ax_b = self.fig_b.add_subplot(111)
        self.ax_b.set_title("Alerts by severity")
        self.canvas_b = FigureCanvasTkAgg(self.fig_b, master=grid)
        self.canvas_b_widget = self.canvas_b.get_tk_widget()
        self.canvas_b_widget.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        # Chart C: MTTD/MTTR distributions (boxplots)
        self.fig_c = Figure(figsize=(4.6,2.8), dpi=100)
        self.ax_c = self.fig_c.add_subplot(111)
        self.ax_c.set_title("MTTD vs MTTR (seconds)")
        self.canvas_c = FigureCanvasTkAgg(self.fig_c, master=grid)
        self.canvas_c_widget = self.canvas_c.get_tk_widget()
        self.canvas_c_widget.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Chart D: Coverage by ATT&CK tactic (bar)
        self.fig_d = Figure(figsize=(4.6,2.8), dpi=100)
        self.ax_d = self.fig_d.add_subplot(111)
        self.ax_d.set_title("Coverage by ATT&CK tactic")
        self.canvas_d = FigureCanvasTkAgg(self.fig_d, master=grid)
        self.canvas_d_widget = self.canvas_d.get_tk_widget()
        self.canvas_d_widget.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

        grid.rowconfigure(0, weight=1)
        grid.rowconfigure(1, weight=1)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        self.refresh()

    def refresh(self):
        snap = self.app.metrics.snapshot()
        self.lbl_total.configure(text=f"Alerts: {snap['alerts_total']}")
        self.lbl_playbooks.configure(text=f"Playbook Runs: {snap['playbook_runs']}")
        self.lbl_cases.configure(text=f"Cases Open: {snap['case_count_open']} / Closed: {snap['case_count_closed']}")
        self.lbl_auto.configure(text=f"Auto-Resolved: {snap['auto_resolved']} | Escalated: {snap['escalated']} | Benign: {snap['false_positive']}")

        # Chart A
        self.ax_a.clear()
        data = [d for _, d in snap["queue_depth_samples"]]
        self.ax_a.plot(data)
        self.ax_a.set_title("Queue depth over time")
        self.ax_a.set_xlabel("Samples")
        self.ax_a.set_ylabel("Depth")
        self.canvas_a.draw_idle()

        # Chart B
        self.ax_b.clear()
        sev = ["low","medium","high","critical"]
        vals = [snap["alerts_by_severity"].get(s,0) for s in sev]
        self.ax_b.bar(sev, vals)
        self.ax_b.set_title("Alerts by severity")
        self.canvas_b.draw_idle()

        # Chart C
        self.ax_c.clear()
        mttd = snap["mttd_samples"] or [0.1]
        mttr = snap["mttr_samples"] or [0.1]
        self.ax_c.boxplot([mttd, mttr], labels=["MTTD","MTTR"])
        self.ax_c.set_title("MTTD vs MTTR (seconds)")
        self.canvas_c.draw_idle()

        # Chart D
        self.ax_d.clear()
        cov = snap["coverage_by_tactic"]
        labels = list(cov.keys())
        values = [cov[k] for k in labels]
        self.ax_d.bar(labels, values)
        self.ax_d.set_title("Coverage by ATT&CK tactic")
        self.ax_d.tick_params(axis='x', labelrotation=45)
        self.canvas_d.draw_idle()

# ---------- Alerts Tab ----------
class AlertsTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app
        self._build()

    def _build(self):
        left = ttk.Frame(self)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right = ttk.Frame(self)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)

        cols = ("id","rule","severity","principal","host","status","playbook")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=24)
        for c in cols:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=120, anchor="w")
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        btns = ttk.Frame(left)
        btns.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(btns, text="Details", command=self._show_selected).pack(side=tk.LEFT, padx=4, pady=4)
        ttk.Button(btns, text="Simulate Process Selected", command=self._simulate_selected).pack(side=tk.LEFT, padx=4, pady=4)

        # Details pane
        self.txt = tk.Text(right, width=60, height=30, font=MONO_FONT)
        self.txt.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    def add_alert_row(self, alert: Alert):
        vals = (alert.id, alert.rule.get("name"), alert.rule.get("severity"), alert.entity.get("principal"), alert.entity.get("host"), alert.status, alert.playbook or "-")
        self.tree.insert("", "end", iid=alert.id, values=vals)

    def update_alert_row(self, alert: Alert):
        if not self.tree.exists(alert.id):
            self.add_alert_row(alert)
            return
        vals = (alert.id, alert.rule.get("name"), alert.rule.get("severity"), alert.entity.get("principal"), alert.entity.get("host"), alert.status, alert.playbook or "-")
        self.tree.item(alert.id, values=vals)

    def _on_select(self, _):
        self._show_selected()

    def _show_selected(self):
        sel = self.tree.selection()
        if not sel: return
        aid = sel[0]
        alert = self.app.alerts.get(aid)
        if not alert: return
        self.txt.delete("1.0", tk.END)
        self.txt.insert(tk.END, json.dumps({
            "id": alert.id,
            "source": alert.source,
            "rule": alert.rule,
            "entity": alert.entity,
            "evidence": alert.evidence,
            "ioc": alert.ioc,
            "raw": alert.raw,
            "status": alert.status,
            "playbook": alert.playbook,
            "case_id": alert.case_id
        }, indent=2))

    def _simulate_selected(self):
        sel = self.tree.selection()
        if not sel: return
        aid = sel[0]
        alert = self.app.alerts.get(aid)
        if not alert: return
        # re-submit to orchestrator for re-processing demo
        cloned = Alert(
            id=f"AL-{short_uuid()}",
            source=alert.source,
            rule=dict(alert.rule),
            entity=dict(alert.entity),
            evidence=dict(alert.evidence),
            ioc=list(alert.ioc),
            raw=dict(alert.raw)
        )
        self.app.orch.submit_alert(cloned)

# ---------- Playbooks Tab ----------
class PlaybooksTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app
        self._build()

    def _build(self):
        paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=1)
        paned.add(right, weight=2)

        self.listbox = tk.Listbox(left, height=20)
        self.listbox.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)

        btns = ttk.Frame(left)
        btns.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(btns, text="Reload", command=self.reload).pack(side=tk.LEFT, padx=4, pady=4)
        ttk.Button(btns, text="Export Selected", command=self._export_selected).pack(side=tk.LEFT, padx=4, pady=4)

        self.txt = tk.Text(right, font=MONO_FONT)
        self.txt.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.reload()

    def reload(self):
        self.listbox.delete(0, tk.END)
        for pb in self.app.pb.all():
            self.listbox.insert(tk.END, f"{pb['name']}  (v{pb.get('version','1.0')})")

    def _on_select(self, _):
        idxs = self.listbox.curselection()
        if not idxs: return
        idx = idxs[0]
        name = self.app.pb.all()[idx]["name"]
        pb = self.app.pb.get(name)
        self.txt.delete("1.0", tk.END)
        self.txt.insert(tk.END, json.dumps(pb, indent=2))

    def _export_selected(self):
        idxs = self.listbox.curselection()
        if not idxs: return
        idx = idxs[0]
        name = self.app.pb.all()[idx]["name"]
        pb = self.app.pb.get(name)
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"{name}.json", filetypes=[("JSON","*.json")])
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(pb, f, indent=2)
        messagebox.showinfo("Export", f"Saved {name} to {path}")

# ---------- Cases Tab ----------
class CasesTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app
        self._build()

    def _build(self):
        paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=2)
        paned.add(right, weight=3)

        cols = ("id","title","severity","status","updated")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=24)
        for c in cols:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=160, anchor="w")
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self.txt = tk.Text(right, font=MONO_FONT)
        self.txt.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=6)

        btns = ttk.Frame(right)
        btns.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(btns, text="Close Case", command=self._close_case).pack(side=tk.LEFT, padx=4, pady=4)
        ttk.Button(btns, text="Mark Contained", command=self._contain_case).pack(side=tk.LEFT, padx=4, pady=4)

        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for c in self.app.cases.list_cases():
            self.tree.insert("", "end", iid=c.id, values=(c.id, c.title, c.severity, c.status, c.updated))

    def _on_select(self, _):
        sel = self.tree.selection()
        if not sel: return
        cid = sel[0]
        cases = {c.id: c for c in self.app.cases.list_cases()}
        case = cases.get(cid)
        if not case: return
        self.txt.delete("1.0", tk.END)
        self.txt.insert(tk.END, json.dumps(case.__dict__, indent=2))

    def _close_case(self):
        sel = self.tree.selection()
        if not sel: return
        cid = sel[0]
        self.app.cases.set_status(cid, "closed", "Closed manually from UI.")
        self.refresh()

    def _contain_case(self):
        sel = self.tree.selection()
        if not sel: return
        cid = sel[0]
        self.app.cases.set_status(cid, "contained", "Contained manually from UI.")
        self.refresh()

# ---------- Simulator Tab ----------
class SimulatorTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app
        self._build()

    def _build(self):
        frm = ttk.Frame(self)
        frm.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        ttk.Label(frm, text="Alert Rate (RPM):").pack(side=tk.LEFT)
        self.var_rpm = tk.IntVar(value=self.app.sim.rate_per_minute)
        ttk.Spinbox(frm, from_=1, to=600, textvariable=self.var_rpm, width=6, command=self._apply).pack(side=tk.LEFT, padx=6)
        ttk.Button(frm, text="Apply", command=self._apply).pack(side=tk.LEFT, padx=6)
        ttk.Button(frm, text="Start", command=self.app.sim.start).pack(side=tk.LEFT, padx=6)
        ttk.Button(frm, text="Stop", command=self.app.sim.stop).pack(side=tk.LEFT, padx=6)

        # Generator preview
        txt = tk.Text(self, font=MONO_FONT, height=20)
        txt.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        txt.insert(tk.END, "Simulator Rules (sample):\n")
        txt.insert(tk.END, json.dumps(Simulator.RULES, indent=2))

    def _apply(self):
        rpm = int(self.var_rpm.get())
        self.app.sim.set_rate(rpm)

# ---------- Settings Tab ----------
class SettingsTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app
        self._build()

    def _build(self):
        frm = ttk.Frame(self)
        frm.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        self._make_switch(frm, "Dry-run", "dry_run", 0)
        self._make_switch(frm, "Kill-switch", "kill_switch", 1)
        self._make_switch(frm, "Require Approval", "require_approval_for_destructive", 2)

        ttk.Label(frm, text="Worker Threads:").grid(row=3, column=0, sticky="w", padx=6, pady=6)
        self.var_workers = tk.IntVar(value=self.app.config_store.get("worker_threads",3))
        ttk.Spinbox(frm, from_=1, to=16, textvariable=self.var_workers, width=6, command=self._apply_workers).grid(row=3, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(frm, text="Max Queue:").grid(row=4, column=0, sticky="w", padx=6, pady=6)
        self.var_q = tk.IntVar(value=self.app.config_store.get("max_queue",1000))
        ttk.Spinbox(frm, from_=100, to=10000, textvariable=self.var_q, width=8, command=self._apply_queue).grid(row=4, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(frm, text="Targets (minutes):").grid(row=5, column=0, sticky="w", padx=6, pady=6)
        ttk.Label(frm, text="MTTD").grid(row=5, column=1, sticky="w")
        self.var_mttd = tk.IntVar(value=self.app.config_store.get("mttd_target_minutes",10))
        ttk.Spinbox(frm, from_=1, to=120, textvariable=self.var_mttd, width=5, command=self._apply_targets).grid(row=5, column=2, sticky="w", padx=6)
        ttk.Label(frm, text="MTTR").grid(row=5, column=3, sticky="w")
        self.var_mttr = tk.IntVar(value=self.app.config_store.get("mttr_target_minutes",60))
        ttk.Spinbox(frm, from_=1, to=480, textvariable=self.var_mttr, width=5, command=self._apply_targets).grid(row=5, column=4, sticky="w", padx=6)

    def _make_switch(self, parent, label, key, row):
        var = tk.BooleanVar(value=self.app.config_store.get(key, False))
        def toggle():
            self.app.config_store[key] = bool(var.get())
            self.app.tab_logs.append(f"{label} -> {self.app.config_store[key]}")
        ttk.Checkbutton(parent, text=label, variable=var, command=toggle).grid(row=row, column=0, sticky="w", padx=6, pady=6)

    def _apply_workers(self):
        self.app.config_store["worker_threads"] = int(self.var_workers.get())
        self.app.tab_logs.append(f"Worker threads set to {self.app.config_store['worker_threads']} (restart app to apply).")

    def _apply_queue(self):
        self.app.config_store["max_queue"] = int(self.var_q.get())
        self.app.tab_logs.append(f"Max queue set to {self.app.config_store['max_queue']} (restart app to apply).")

    def _apply_targets(self):
        self.app.config_store["mttd_target_minutes"] = int(self.var_mttd.get())
        self.app.config_store["mttr_target_minutes"] = int(self.var_mttr.get())
        self.app.tab_logs.append(f"Targets updated: MTTD={self.app.config_store['mttd_target_minutes']}m MTTR={self.app.config_store['mttr_target_minutes']}m")

# ---------- Logs Tab ----------
class LogsTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent)
        self.app = app
        self._build()

    def _build(self):
        self.txt = tk.Text(self, font=MONO_FONT)
        self.txt.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=6)
        self._refresh()

    def _refresh(self):
        self.txt.delete("1.0", tk.END)
        for line in self.app.log.tail(1000):
            self.txt.insert(tk.END, line + "\n")
        self.after(2000, self._refresh)

    def append(self, line: str):
        self.txt.insert(tk.END, line + "\n")
        self.txt.see(tk.END)


def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()

# ==============================================================================
# Appendix: MITRE ATT&CK tactics reference & help text (for learning)
# ==============================================================================
# TACTIC: Reconnaissance - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Resource Development - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Initial Access - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Execution - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Persistence - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Privilege Escalation - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Defense Evasion - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Credential Access - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Discovery - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Lateral Movement - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Collection - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Command and Control - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Exfiltration - Placeholder description and examples of techniques used in playbooks.
# TACTIC: Impact - Placeholder description and examples of techniques used in playbooks.

# USER HELP
# ----------
# * Dashboard: observe system health and metrics; charts update continuously.
# * Alerts: live feed of simulated alerts; select any row to view JSON details.
# * Playbooks: browse built-in playbooks; export JSON; wiring is rule_id-based.
# * Cases: auto-opened for each alert by default; view audit trail in JSON.
# * Simulator: control alert rate (RPM). Start/Stop from toolbar or this tab.
# * Settings: dry-run prevents actions from calling connectors; kill-switch logs only.
# * Logs: rolling log of orchestration steps with timestamps.
#
# DESIGN NOTES
# ------------
# * Orchestrator evaluates a tiny decision DSL (SafeExpr) safe from arbitrary code exec.
# * Connectors are mocks: adapt them to real APIs (Okta/AAD, EDRs, M365/Gmail, AWS/Azure).
# * CaseManager persists audit entries and maintains status and summaries.
# * MetricsStore aggregates stats for charts: queue depth, MTTR/MTTD distributions, etc.
#
# EXTEND
# ------
# - Add new playbooks to PlaybookRegistry.register(...).
# - Map SIEM rule -> playbook in PlaybookRegistry.choose_for_rule(...).
# - Implement real actions in connectors and flip dry_run=False.
# - Persist state periodically or to a database backend.
# - Add authentication & RBAC on the GUI if turning into a multi-user tool.
#
# TESTING
# -------
# - For quick sanity: run the app; press Start Sim; observe alerts and cases.
# - Change dry-run off and see mock connectors being "called".
# - Use the Alerts tab "Simulate Process Selected" to re-run an alert through the pipeline.
#
# SAFETY
# ------
# - This is a learning tool; it performs no destructive external actions.
# - If adapted to real infra, ensure approvals and kill-switch are respected.
# Additional Example Playbook Variants (commented out for brevity)

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 1 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 2 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 3 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 4 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 5 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 6 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 7 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 8 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 9 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 10 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 11 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 12 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 13 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 14 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 15 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 16 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 17 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 18 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 19 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 20 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 21 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 22 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 23 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 24 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 25 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 26 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 27 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 28 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 29 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 30 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 31 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 32 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 33 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }
# --- Variant block 34 ---

# {
#   "name": "Phishing_Triage_v2",
#   "version": "2.0.0",
#   "tactics": ["Initial Access", "Credential Access"],
#   "triggers": [{"rule_id": "R-2001", "tag": "phishing"}],
#   "steps": [
#       {"enrich": {"sender_reputation": true, "url_sandbox": true, "vt_hash": true}},
#       {"decision": {
#           "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 80]},
#           "on_true": "quarantine_email",
#           "on_false": "close_benign"
#       }},
#       {"action": "quarantine_email"},
#       {"notify": {"channel": "user", "template": "phish-education-v2"}},
#       {"case_update": {"status": "contained", "summary": "Quarantined + escalated training."}}
#   ]
# }