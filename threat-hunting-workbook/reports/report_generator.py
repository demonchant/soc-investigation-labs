"""Threat Hunting Workbook Report Generator."""
from datetime import datetime

class ReportGenerator:
    def generate(self, results):
        hits  = [r for r in results if r["status"] == "HIT"]
        misses = [r for r in results if r["status"] == "MISS"]
        r = []
        r.append("=" * 65)
        r.append("  THREAT HUNTING WORKBOOK — HUNT RESULTS")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Hunts     : " + str(len(results)) +
                 "  |  " + str(len(hits)) + " HIT  |  " + str(len(misses)) + " MISS")
        r.append("=" * 65)

        r.append("\n  SUMMARY\n")
        for res in results:
            icon = "[HIT ]" if res["status"] == "HIT" else "[MISS]"
            r.append("  " + icon + " " + res["hunt_id"] + " — " + res["hunt_name"])

        r.append("\n\n  DETAILED FINDINGS\n")
        for res in results:
            r.append("  " + res["hunt_id"] + " : " + res["hunt_name"])
            r.append("  Hypothesis  : " + res["hypothesis"][:120])
            r.append("  MITRE       : " + res["mitre"])
            r.append("  Status      : " + res["status"] +
                     (" (" + str(res["finding_count"]) + " evidence item(s))" if res["status"]=="HIT" else " — no evidence found"))

            if res["findings"]:
                r.append("  Evidence    :")
                for f in res["findings"]:
                    r.append("    [" + res["severity"].upper() + "] " + f.get("detail",""))
                    for k, v in f.items():
                        if k != "detail" and v:
                            r.append("      " + str(k).ljust(16) + ": " + str(v)[:80])
                    r.append("")
            else:
                r.append("  No evidence found — hypothesis not confirmed in current dataset.\n")
            r.append("  " + "-" * 61)
            r.append("")

        r.append("=" * 65)
        return "\n".join(r)
