"""
run_demo.py - tries the 3 services together on the sample log.
Run from the project root:  python run_demo.py
"""
import os

# Demo defaults so it runs without a .env file (real settings come from .env)
os.environ.setdefault("EMAIL_DRY_RUN", "true")
os.environ.setdefault("EMAIL_TO", "devops-team@example.com")

from app.services.regex_service import extract_incidents
from app.services.masking_service import mask_text_with_stats
from app.services.email_service import handle_tool_call

LOG_FILE = "sample_logs/app.log"

incidents = extract_incidents(LOG_FILE)
print(f"\n== 1. Extracted {len(incidents)} incident group(s) ==")
for inc in incidents:
    print(f"[{inc.level}] {inc.service} x{inc.count}  {inc.sample_message[:70]}")

top = incidents[0]
print("\n== 2. Masked text that would go to embeddings / Gemini ==")
masked_text, stats = mask_text_with_stats(top.to_embedding_text())
print(masked_text)

# Masking stats across ALL incidents (the sample log contains emails, IPs, a card)
total = {}
for inc in incidents:
    _, found = mask_text_with_stats(inc.to_embedding_text())
    for key, value in found.items():
        total[key] = total.get(key, 0) + value
print("\nMasked items across all incidents:", total)

print("\n== 3. Email tool (simulating a Gemini tool call) ==")
result = handle_tool_call(
    "send_critical_alert",
    {
        "title": "Payment service failing after v2.3.1 deployment",
        "severity": "critical",
        "affected_service": top.service,
        "root_cause": "DB connection pool reduced from 20 to 5 in release v2.3.1",
        "suggested_fix": "Roll back to v2.3.0 or restore db_pool_size=20",
        "confidence": 0.86,
    },
)
print("Result:", result)