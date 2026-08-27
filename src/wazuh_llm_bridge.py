import os
import json
import time
import requests
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

WAZUH_ALERTS_PATH = os.getenv(
    "WAZUH_ALERTS_PATH",
    "/var/ossec/logs/alerts/alerts.json"
)
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")


def query_llm(prompt):
    if LLM_PROVIDER == "openai":
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json={
                "model": MODEL_NAME,
                "messages": [{"role": "user", "content": prompt}]
            }
        )
        return response.json()["choices"][0]["message"]["content"]

    elif LLM_PROVIDER == "huggingface":
        headers = {"Authorization": f"Bearer {HUGGINGFACE_API_KEY}"}
        response = requests.post(
            f"https://api-inference.huggingface.co/models/{MODEL_NAME}",
            headers=headers,
            json={"inputs": prompt}
        )
        return response.json()[0]["generated_text"]

    elif LLM_PROVIDER == "ollama":
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": MODEL_NAME, "prompt": prompt}
        )
        output = ""
        for line in response.iter_lines():
            if line:
                data = json.loads(line.decode("utf-8"))
                if "response" in data:
                    output += data["response"]
        return output.strip()

    else:
        return "Unsupported LLM provider"


def process_alert(alert):
    # Pull rule information from alert safely
    rule = alert.get("rule", {})
    description = rule.get("description", "No description")

    # Some Wazuh JSONs use ints, some use strings.
    # Normalize rule ID to int when possible.
    raw_rule_id = rule.get("id", "")
    try:
        rule_id = int(raw_rule_id)
    except Exception:
        # fallback: try to strip and convert, else -1
        try:
            rule_id = int(str(raw_rule_id).strip())
        except Exception:
            rule_id = -1

    level = rule.get("level", 0)
    try:
        level = int(level)
    except Exception:
        # fallback if level is string or missing
        try:
            level = int(str(level).strip())
        except Exception:
            level = 0

    print(f"[LLM] Processing rule {rule_id}: {description} (level={level})")

    # --- RULES TO ENRICH (whitelist) ---
    # Use integers here.
    rule_ids_to_enrich = [
        5503, 5551, 5760, 5763, 40112,       # Fedora SSH brute force
        60122, 60204, 60107, 60115, 60104,  # Windows security events
        31168,                               # Shellshock
        31103,                               # SQL injection
    ]

    # Enrichment decision:
    # - If severity >= 7 -> enrich
    # - OR if rule id is in whitelist -> enrich
    # - Otherwise skip
    if level >= 7:
        print(f"[LLM] Enriching due to severity >=7 (rule {rule_id}).")
    elif rule_id in rule_ids_to_enrich:
        print(f"[LLM] Enriching because rule {rule_id} is whitelisted.")
    else:
        print(
            f"[LLM] Skipping rule {rule_id}: "
            "not high severity and not whitelisted."
        )
        return  # skip noise

    # Build prompt for the LLM
    prompt = f"""
Analyze this Wazuh alert:
Description: {description}
Severity Level: {level}
Full JSON: {json.dumps(alert)}

Provide:
- A short summary
- Whether it's a Linux or Windows event
- Threat classification
- Recommended actions
- Any indicators of compromise (IOCs)
"""

    try:
        result = query_llm(prompt)
        print("\n=== LLM Analysis ===")
        print(result)
        print("====================\n")
    except Exception as e:
        print(f"[LLM] Error querying LLM: {e}")


def tail_alerts():
    with open(WAZUH_ALERTS_PATH, "r") as f:
        f.seek(0, os.SEEK_END)  # Go to the end of the file

        while True:
            line = f.readline()

            if not line:
                time.sleep(1)
                continue

            try:
                alert = json.loads(line)
                process_alert(alert)
            except Exception as e:
                print(f"Error processing alert: {e}")


if __name__ == "__main__":
    print("🔍 Wazuh-LLM bridge running...")
    tail_alerts()
