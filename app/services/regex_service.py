"""
Reads a log file, extracts ERROR / CRITICAL / FATAL lines together with the
surrounding context, and groups duplicate errors into incidents.

Expected log format (same as sample_logs/app.log):
    2026-11-23 14:03:58,100 ERROR [payment-service] message ...

Lines that do not match this format (for example stack traces) are treated as
continuation lines of the entry above them.
"""

import sys
from app.core.regex_extractor import extract_incidents


# --------------------------------------------------------------------------- #
# Quick manual test:  python -m services.regex_extractor sample_logs/app.log
# --------------------------------------------------------------------------- #
def get_incidents_from_logs():
    path = sys.argv[1] if len(sys.argv) > 1 else "app/Temp/app.log"
    incidents = extract_incidents(path)
    print(f"Found {len(incidents)} incident group(s) in {path}\n")
    return incidents
    
# if __name__ == "__main__":
#     path = sys.argv[1] if len(sys.argv) > 1 else "app/Temp/app.log"
#     incidents = extract_incidents(path)
#     print(f"Found {len(incidents)} incident group(s) in {path}\n")
#     for inc in incidents:
#         print(f"[{inc.level}] {inc.service} x{inc.count}  (line {inc.first_line_no})")
#         print(f"   {inc.sample_message}")