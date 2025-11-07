# Automated-Incident-Response-IR-Simulator

python playbook_ir_gui.py
Click Start Sim to generate alerts

Toggle Dry‑run / Kill‑switch / Require Approval

Explore tabs: Dashboard, Alerts, Playbooks, Cases, Simulator, Settings, Logs

Use File → Save/Load State to persist your session

🧱 Architecture (High‑Level)
css
Always show details

Copy code
[ Simulator / SIEM-like Rules ]
                │
                ▼
        [ Alert Queue ]  ──► (depth metrics)
                │
                ▼
     [ Orchestrator Workers ]  ──► Enrich → Decision → (Approval?) → Actions
                │
                ├──► [ Case Manager ] ──► Audit Trail / Status / Artifacts
                ├──► [ Connectors ] (IdP, EDR, Email, Cloud)  ← (mocked)
                └──► [ Metrics Store ] ──► Charts (Queue, MTTD/MTTR, Coverage)
Connectors (mock): Okta/AAD‑like IdP, EDR isolate/snapshot, M365/Gmail quarantine, Cloud key revoke/block.

🗂️ Included Playbooks
Playbook	Rule ID/Tag	Tactics (ATT&CK)	Key Actions
Phishing_Triage_v1	R-2001 / phishing	Initial Access, Credential Access	quarantine email, notify user
Impossible_Travel_v1	R-1029	Initial Access	revoke sessions, force MFA reset (approval)
Malware_On_Endpoint_v1	R-3100	Execution, Persistence, Defense Evasion	isolate host (approval), triage pkg
Privilege_Escalation_v1	R-4010	Privilege Escalation	revoke admin rights, rotate keys
Ransomware_Burst_v1	R-9001	Impact, C2	isolate host (approval), block C2 IoCs, snapshot
Cloud_Access_Key_Leak_v1	R-7007	Credential Access, Exfiltration	revoke cloud keys, apply block policy

Mapping: PlaybookRegistry.choose_for_rule() wires SIEM rule IDs/tags to a playbook.

🧩 Configuration (GUI Toggles)
Dry‑run: No external actions executed (safe default)

Kill‑switch: Log only; orchestration steps recorded without actions

Require Approval: Gated for destructive actions (isolation, revocation)

Workers: number of orchestrator threads (Settings tab)

Queue size: max alerts buffered (Settings tab)

Targets: MTTD/MTTR SLO minutes (Settings tab)

Simulator RPM: alerts/minute (Toolbar & Simulator tab)

Persisted keys (in state JSON):

json
Always show details

Copy code
{
  "dry_run": true, "kill_switch": false, "require_approval_for_destructive": true,
  "worker_threads": 3, "max_queue": 1000, "mttr_target_minutes": 60, "mttd_target_minutes": 10,
  "random_seed": 1337, "log_level": "INFO", "auto_open_cases": true, "save_path": "ir_sim_state.json"
}
🖼️ Screenshots (placeholders)
Add images after first run to your repo:

bash
Always show details

Copy code
/images/dashboard.png
/images/alerts.png
/images/cases.png
/images/playbooks.png
Markdown snippet:

md
Always show details

Copy code
![Dashboard](images/dashboard.png)
![Alerts](images/alerts.png)
![Cases](images/cases.png)
![Playbooks](images/playbooks.png)
🧠 Extending Playbooks
Edit PlaybookRegistry and register a new entry:

python
Always show details

Copy code
registry.register({
  "name": "Custom_Playbook_v1",
  "version": "1.0.0",
  "tactics": ["Discovery"],
  "triggers": [{"rule_id": "R-1234", "tag": "custom"}],
  "steps": [
    {"enrich": {"edr_context": True}},
    {"decision": {
        "expression": {"fn":"gte","args":[{"fn":"score","args":["risk_score"]}, 70]},
        "on_true": "isolate_host", "on_false": "document_and_close"}},
    {"action": "isolate_host"},
    {"case_update": {"status": "contained", "summary": "Auto-contained by custom playbook"}}
  ]
})
Decision DSL uses a safe evaluator (SafeExpr) with helpers: gte, lte, gt, lt, eq, contains, anytrue, alltrue, score.

🔧 Troubleshooting
❌ AttributeError: module 'time' has no attribute 'datetime'
✅ Fixed in current code: utcnow() uses datetime.now(timezone.utc).

❌ ImportError: No module named '_tkinter' (Linux)
✅ Install Tk: sudo apt-get install python3-tk

❌ Cannot load backend 'TkAgg'
✅ Ensure Tk installed; avoid headless environments

❌ Blank charts
✅ Check that Simulator is running; data feeds drive the dashboards

🤝 Contributing
Fork & create feature branch: feat/your-idea

Keep code type‑hinted & documented

Test on at least one OS (Win/macOS/Linux)

Submit PR with a brief demo (gif/screenshot)

📄 License
This project is released under the MIT License. See LICENSE.
(Feel free to change the license for your repo if needed.)

🙏 Credits
Author: Dr. Mohammed Tawfik — kmkhol01@gmail.com

Built with ❤️ using Python, Tkinter & Matplotlib.

Thanks to the security community for inspiration (NIST 800‑61, SANS PICERL, MITRE ATT&CK).

🗺️ Roadmap Ideas
Real API connectors (Okta/AAD, EDR, M365/Gmail, AWS/Azure)

CACAO 2.0 playbook import/export

Risk scoring models & anomaly simulation

Case evidence hashing & export bundle

CI tests (unit + scenario) and packaging

