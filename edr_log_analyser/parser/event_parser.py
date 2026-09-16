"""
EDR Event Parser — Normalises Windows Security Event Log and Sysmon events
into a flat, consistent schema for the detection engine.
Covers: process creation (4688/Sysmon 1), logon events (4624/4625),
registry changes (Sysmon 13), file creation (Sysmon 11).
"""
import json, logging
logger = logging.getLogger(__name__)

REQUIRED = ["timestamp", "host", "event_type"]

EVENT_ID_LABELS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4688: "Process Creation",
    4698: "Scheduled Task Created",
    4720: "User Account Created",
    4732: "Member Added to Security Group",
    13:   "Sysmon: Registry Value Set",
    11:   "Sysmon: File Created",
    3:    "Sysmon: Network Connection",
    1:    "Sysmon: Process Creation",
}


class EventParser:
    def parse(self, file_path):
        try:
            with open(file_path) as f:
                raw = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error("Failed to load EDR events: " + str(e))
            return []

        parsed = []
        skipped = 0
        for i, ev in enumerate(raw):
            if not all(field in ev for field in REQUIRED):
                skipped += 1
                continue
            ev["event_id_label"] = EVENT_ID_LABELS.get(ev.get("event_id"), "Unknown")
            parsed.append(ev)

        if skipped:
            logger.warning("Skipped " + str(skipped) + " malformed event(s).")
        logger.info("Parsed " + str(len(parsed)) + " EDR event(s).")
        return parsed
