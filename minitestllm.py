from openai import OpenAI
import pandas as pd
import os
import glob
import json
from openai import OpenAI
# -------------------------
# INIT CLIENT
# -------------------------
client = OpenAI()

# -------------------------
# PATH TO CHUNKS
# -------------------------
chunk_folder = r"C:\Users\tcsim\PycharmProjects\Capstone-LLM-Project-\Logs_Normal\test1"

chunk_files = glob.glob(os.path.join(chunk_folder, "*.csv"))

chunk_files = sorted(
    chunk_files,
    key=lambda x: int(os.path.basename(x).replace("chunk", "").replace(".csv", ""))
)

# -------------------------
# STORAGE
# -------------------------
all_logs_analysis = []
all_top5_candidates = []

# -------------------------
# PROCESS CHUNKS
# -------------------------
for file in chunk_files:
    print(f"Processing: {os.path.basename(file)}")

    df = pd.read_csv(file)

    # 🔥 CHEAPER FORMAT (IMPORTANT)
    chunk_logs_str = "\n".join(
        f"{row.get('EventID')} | {row.get('EventName')} | {row.get('MessageText')}"
        for _, row in df.iterrows()
    )

    prompt = f"""
You are a Wazuh System information event manager.

Analyze the logs and detect suspicious activity.

Tasks:
Assign a suspicion score (1-15)
Label as "Yes" or "No"
write a human-readable summary explaining why each log was flagged
Identify top 5 most suspicious logs


IMPORTANT:
- Logs are chronological
0–2: Normal system activity (no security relevance)
3–5: Low-risk errors or user mistakes (usually harmless)
6–8: Potentially suspicious behavior (needs review)
9–11: Strong suspicious indicators (possible attack or compromise)
12–15: Highly likely malicious activity or active attack indicators
These may indicate an attack against a specific application.
These may indicate an attack or simply signal that a user has forgotten their credentials.
These also include errors regarding the "admin" (root) account.
It also includes security relevant actions such as the activation of a sniffer or similar activities.
These also include frequent IDS events and frequent errors.
These rules are scanned before all the others, include events with no security relevance
-Do not assume an event is malicious just because it could be used in an attack.
-Events like service installation, configuration changes, or system errors are often normal unless there is clear evidence of abuse.
Return ONLY valid JSON no markdown, no extra text
- Only use information explicitly present in the provided logs.
- DO NOT use external knowledge about Event IDs.
- DO NOT guess, assume, or infer missing details.
- DO NOT create explanations that are not directly supported by the log content.
It is acceptable and expected that no suspicious activity may be present.
Do NOT fabricate suspicious activity to fill the top 5 list.
OUTPUT FORMAT:
{{
  "chunk_all_logs": [
    {{
      "Full_Log": "",
      "Suspicion_Score": 1-15,
      "Suspicious": "Yes/No",
      "Reason": ""
    }}
  ],
  "chunk_top_5": [
    {{
      "Full_Log": "",
      "Suspicion_Score": 1-15,
      "human-readable_summary": ""
    }}
  ],
  "chunk_summary": ""
}}

LOGS:
{chunk_logs_str}
"""

    # -------------------------
    # API CALL
    # -------------------------
    response = client.chat.completions.create(
        model="gpt-4-turbo",
        temperature=0,
        messages=[
            {"role": "system", "content": "You are a Wazuh System information event manager."},
            {"role": "user", "content": prompt}
        ]
    )

    output_text = response.choices[0].message.content

    # -------------------------
    # SAFE JSON PARSE (NO REGEX)
    # -------------------------
    try:
        chunk_json = json.loads(output_text)
    except Exception as e:
        print(f"JSON error in {file}: {e}")
        print(output_text)
        continue

    # -------------------------
    # COLLECT RESULTS
    # -------------------------
    all_logs_analysis.extend(chunk_json["chunk_all_logs"])
    all_top5_candidates.extend(chunk_json["chunk_top_5"])

# -------------------------
# GLOBAL TOP 5
# -------------------------
top5_df = pd.DataFrame(all_top5_candidates)

top5_df["Suspicion_Score"] = pd.to_numeric(top5_df["Suspicion_Score"], errors="coerce")

top5_df = top5_df.sort_values(by="Suspicion_Score", ascending=False).head(5)

top5_df.to_csv("testTop5_Suspicious_Logs.csv", index=False)

# -------------------------
# ALL LOGS OUTPUT
# -------------------------
all_logs_df = pd.DataFrame(all_logs_analysis)

all_logs_df.to_csv("testAll_Logs_Analysis.csv", index=False)

print("DONE")
print("Created:")
print("- testAll_Logs_Analysis.csv")
print("- testTop5_Suspicious_Logs.csv")