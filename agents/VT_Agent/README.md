# VT Agent

## Agent Purpose

The VT (VirusTotal) Agent should threat intelligence capabilities by interfacing with VirusTotal services to analyze indicators of compromise (IOCs) and download malware samples for security analysis.

## Implemented Functionalities

- **Threat Intelligence Lookup**: Analyze multiple host-based indicators (HBIs) and network-based indicators (NBIs) including IPs, FQDNs, and file hashes

## Associated Tools

### `vt_ti_lookup`
- **Purpose**: Perform threat intelligence lookup on multiple indicators in parallel
- **Input**: List of indicators (IPs, FQDNs, hashes)
- **Output**: Security details including reputation, classification, risk scores, and detection information


## Endpoint Configuration

The VT Agent requires a webhook endpoint to be configured in the `AGENT_ENDPOINTS` dictionary inside `server.py`:

```python
"VT_Agent": "https://your-domain.com/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>"
```

## Usage Examples

**Threat Intelligence Lookup:**
```
lookup "23.12.4.34","cd5c8af95851ace218adb1aac09cf16042ee78ae"
```
