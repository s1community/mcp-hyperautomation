# Agents

## What is an Agent?

Agents are the backbone of the **Interactive Security Orchestrator** architecture, each representing a collective of features all related to the same domain (Detections, Agent Management, Case Management, DataLake, etc..).

This means that **instead of building monololithic workflows**, which are good prototyping, but but don't scale and are generally hard to main over longer periods of time, **we rely on a modular architecture** where each each group of domain-specific capabilities is exposed by a single entity that we call Agent.

Modular architectures happen to also be the golden standard when building SOAR orchestrations and Agents embody that paradigm in HA.



---
## Release Notes
## 2025-08-23 (mcp-hyperautomation v0.1)

### New Features

- First release of the MCP server for HyperAutomation
  - Four Active and One Passive Agents release:
    - **Case Manager**
    - **SDL**
    - **Asset Manager**
    - **VT**
    - **DB Manager**
  - Google Big Query is the default choice for temporarily storing Agents' results
 
### Improvements
- N/A
### Bugs
- N/A
---
