from __future__ import annotations

"""Schema version constants for intervention_ledger's own records -- M0
("Freeze schemas") from investigacion_y_novedad/13_plan_construccion_forge_dt_v3.md.
Does NOT version forensic_twin's or fault_injection's own already-stable
record formats (those are untouched); this only versions the NEW ledger
entry format this module introduces.
"""

LEDGER_SCHEMA_VERSION = "1.0.0"

# Valid values for a ledger entry's "class" field -- matches the study's own
# taxonomy (section 8.3's Intervention Ground-Truth Ledger table, "class"
# row: fault/cyberattack/misconfiguration/benign-control).
INTERVENTION_CLASSES = ("fault", "cyberattack", "misconfiguration", "benign-control")

# Valid values for "source" -- which real subsystem produced the underlying
# intervention this ledger entry is a projection of. Never a third source:
# the ledger only ever reuses an already-real record, never originates one.
INTERVENTION_SOURCES = ("fault_injection", "attack_lab")

# Valid values for "phase".
INTERVENTION_PHASES = ("applied", "reverted", "executed")
