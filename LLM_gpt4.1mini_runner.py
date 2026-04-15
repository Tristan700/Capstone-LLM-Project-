#good one
from openai import OpenAI
import pandas as pd
import os
import glob
import json
import re

# Initialize OpenAI client
client = OpenAI()

# Folder containing chunk CSVs
chunk_folder = r"C:\Users\tcsim\PycharmProjects\Capstone-LLM-Project-\Chunked_filesDataset1scored"

# Get all CSV chunks and sort them numerically
chunk_files = glob.glob(os.path.join(chunk_folder, "*.csv"))
chunk_files = sorted(
    chunk_files,
    key=lambda x: int(os.path.basename(x).replace("chunk", "").replace(".csv", ""))
)

# To store all logs with LLM analysis
all_logs_analysis = []

# To store top 5 suspicious logs from all chunks
all_top5_candidates = []

# Process chunks one by one
for file in chunk_files:
    print(f"Processing chunk file: {os.path.basename(file)}")

    df = pd.read_csv(file)
    chunk_logs = df.to_dict(orient="records")

    # Convert logs to string for LLM
    chunk_logs_str = json.dumps(chunk_logs, indent=2)


    prompt = f"""
You are a cybersecurity SOC analyst.

Tasks:
1. For these logs, assign a suspicion score (1-15), indicate if it is suspicious (Yes/No), 
   and provide a short human-readable reason.
2. Also identify the top 5 most suspicious logs in this chunk.

Important: Logs are chronological. Use context from previous logs (last 20 lines are included).

Instructions for output:
- Return structured JSON with two keys: "chunk_top_5" and "chunk_all_logs".
- "chunk_top_5": list of the top 5 logs with fields:
    - Full_Log
    - Suspicion_Score (1-15)
    - Explanation
- "chunk_all_logs": list of all logs in this chunk with fields:
    - Full_Log
    - Suspicion_Score (1-15)
    - Suspicious ("Yes" if score >=5, else "No")
    - Reason

Logs:
{chunk_logs_str}
"""

    # Send to LLM
    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        temperature=0,
        messages=[
            {"role": "system", "content": "You are a SOC analyst."},
            {"role": "user", "content": prompt}
        ]
    )

    output_text = response.choices[0].message.content

    # Extract JSON from LLM output
    try:
        json_match = re.search(r'\{.*\}', output_text, re.DOTALL)
        chunk_json = json.loads(json_match.group())
    except Exception as e:
        print(f"Error parsing JSON from {os.path.basename(file)}: {e}")
        print("Raw LLM output:", output_text)
        continue  # Skip this chunk if parsing fails

    # Append all chunk logs to the combined all_logs_analysis list
    all_logs_analysis.extend(chunk_json["chunk_all_logs"])

    # Collect top 5 candidates for overall top 5
    all_top5_candidates.extend(chunk_json["chunk_top_5"])

# Compute overall top 5 based on Suspicion_Score
top5_df = pd.DataFrame(all_top5_candidates)
top5_df = top5_df.sort_values(by="Suspicion_Score", ascending=False).head(5)
top5_df.to_csv("Top5_Suspicious_LogsDataset1scored.csv", index=False)

# Save all logs with LLM scoring
all_logs_df = pd.DataFrame(all_logs_analysis)
all_logs_df.to_csv("All_Logs_AnalysisDataset1scored.csv", index=False)

print("Done! Two CSV files created:")
print("1. Top5_Suspicious_Logs2.csv")
print("2. All_Logs_Analysis2.csv")