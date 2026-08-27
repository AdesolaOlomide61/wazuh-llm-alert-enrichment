# LLM-Enhanced Wazuh SIEM Alert Enrichment

## Overview
This project presents a post-detection contextual alert enrichment system integrating Wazuh SIEM with a Large Language Model (LLaMA 3) to improve Security Operations Centre (SOC) triage efficiency.

---

## Architecture
The system processes alerts from Wazuh and enriches them using a Python-based middleware and LLM.

**Pipeline Flow:**
Endpoints → Wazuh Agents → Wazuh Manager → alerts.json → Python Bridge → LLaMA 3 → Enriched Alerts

---

## Features
- Post-detection contextual alert enrichment
- MITRE ATT&CK mapping
- Indicator of Compromise (IOC) extraction
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
  
