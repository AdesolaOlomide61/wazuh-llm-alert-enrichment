# LLM-Enhanced Wazuh SIEM Alert Enrichment

## Overview
This project presents a post-detection contextual alert enrichment framework integrating Wazuh SIEM with a locally deployed Large Language Model (LLaMA 3) to provide additional contextual information for Security Operations Centre (SOC) alert triage. Wazuh remains responsible for rule-based detection and alert generation, while the LLM operates as a separate enrichment layer for selected alerts.

---

## Architecture
The framework operates as a post-detection enrichment layer alongside Wazuh. Wazuh remains responsible for monitoring endpoints, applying its rule-based detection logic, and generating security alerts. A Python-based bridge monitors the Wazuh alert stream and applies the configured alert-selection criteria before submitting eligible alerts to the locally deployed LLaMA 3 model through Ollama.

**Pipeline Flow:**
Endpoints → Wazuh Agents → Wazuh Manager → alerts.json → Alert Selection → Python Bridge → Ollama/LLaMA 3 → Contextual Enrichment

---

## Features
- Post-detection contextual alert enrichment
- MITRE ATT&CK contextual mapping were generated
- Identification of relevant Indicators of Compromise (IOCs)
- Actionable remediation recommendations
- Latency tracking analysis

  ---

  ## Technologies Used
  
  - Wazuh SIEM 4.12.0
  - Python 3
  - Ollama runtime
  - LLaMA 3 8B ('llama3:Latest')
  - GGUF Q4_0 quantisation
  - Oracle VirtualBox
  - Kali Linux (attacker system)
  - Fedora Linux (monitored Linux endpoint)
  - Windows 11 Education (monitored Windows endpoint)
 
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
  
