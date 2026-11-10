"""lantern_siem: deliver Lantern findings to a SIEM.

Pipeline layers:
    validate  -> data-quality checks, flags, quarantine (config/dq_rules.yaml)
    normalize -> canonical, SIEM-agnostic finding
    map       -> per-SIEM field mapping (config/mappings/*.yaml)
    deliver   -> per-SIEM sender (senders/)

Every run writes its own folder under runs/<run_id>/ (see runlog.py).
"""

__version__ = "0.1.0"
