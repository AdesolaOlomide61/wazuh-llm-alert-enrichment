# LLM-Enhanced Wazuh SIEM Alert Enrichment

## Overview
This project presents a post-detection contextual alert enrichment framework integrating Wazuh SIEM with a locally deployed Large Language Model (LLaMA 3) to provide additional contextual information for Security Operations Centre (SOC) alert triage. Wazuh remains responsible for rule-based detection and alert generation, while the LLM operates as a separate enrichment layer for selected alerts.

---

## Architecture
The system processes alerts from Wazuh and enriches them using a Python-based middleware and LLM.

**Pipeline Flow:**
Endpoints → Wazuh Agents → Wazuh Manager → alerts.json → Python Bridge → LLaMA 3 → Enriched Alerts

---

## Features
- Post-detection contextual alert enrichment
- MITRE ATT&CK contextual mapping were generated
- Identification of relevant Indicators of Compromise (IOCs)
- Actionable remediation recommendations
- Latency tracking analysis

  ---

  ## Technologies Used
  - Wazuh SIEM
  - Python
  - Ollama (LLaMA 3)
  - Oracle VirtualBox
 
  ---

  ## Repository Contents
  - `wazuh_llm_bridge.py` - Core enrichment pipeline
  - `latency_analysis.py` - Latency evaluation
  - Sample alerts (raw and enriched)

   ---

  ## Reproducibility
  This repository provides implementation, including scripts, configuration, and experimental artifacts, is provided to support reproducibility of the research.

  ---

  ## Author
  Adesola Olomide
  
