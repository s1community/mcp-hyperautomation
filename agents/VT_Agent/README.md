# VT Agent

## Agent Purpose

The VT (VirusTotal) Agent provides threat intelligence capabilities by interfacing with VirusTotal services to analyze indicators of compromise (IOCs) and download malware samples for security analysis.

## Capabilities/Functionalities Exposed

- **Threat Intelligence Lookup**: Analyze multiple host-based indicators (HBIs) and network-based indicators (NBIs) including IPs, FQDNs, and file hashes
- **Malware Sample Download**: Retrieve malware samples associated with hash indicators for further analysis
- **Multi-Format Support**: Handles MD5, SHA-1, and SHA-256 hash formats
- **Comprehensive Reporting**: Provides detailed security classifications, risk scores, and detection information

## Associated Tools

### `vt_ti_lookup`
- **Purpose**: Perform threat intelligence lookup on multiple indicators
- **Input**: List of indicators (IPs, FQDNs, hashes)
- **Output**: Security details including reputation, classification, risk scores, and detection information
- **Presentation**: Results formatted in markdown table with risk highlighting

### `vt_download_sample`
- **Purpose**: Download malware samples associated with hash indicators
- **Input**: List of file hashes (MD5, SHA-1, SHA-256)
- **Output**: Download links or status information from the database
- **Limitation**: Only works with hash indicators (not IPs or FQDNs)

## Endpoint Configuration

The VT Agent requires a webhook endpoint to be configured in the `AGENT_ENDPOINTS` dictionary:

```python
"VT_Agent": "https://your-domain.com/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>"
```

## Usage Examples

**Threat Intelligence Lookup:**
```python
await vt_ti_lookup(['8.8.8.8', 'google.com', 'hash_value'])
```

**Sample Download:**
```python
await vt_download_sample(['md5_hash', 'sha256_hash'])
```
