# CASEMANAGER Agent

## Agent Purpose

The CASEMANAGER Agent provides comprehensive alert and case management capabilities. It enables security analysts to list, filter, and manage security alerts across different detection products, and add investigative notes to alerts for case documentation and collaboration.

## Capabilities/Functionalities Exposed

- **Alert Discovery**: List and filter security alerts with flexible time ranges
- **Multi-Product Support**: Handle alerts from EDR, CWS (Cloud Workload Security), and Identity detection products
- **Advanced Filtering**: Filter by asset names, alert IDs, detection products, and time ranges
- **Note Management**: Add investigative notes to alerts for documentation and team collaboration
- **Historical Analysis**: Query alerts over the last 3 months by default

## Associated Tools

### `casemanager_list_alerts`
- **Purpose**: List and filter security alerts across all detection products
- **Input**: List of condition dictionaries for filtering (use `[{}]` for all alerts in last 3 months)
- **Output**: Comprehensive alert information including detection details, affected assets, and timestamps
- **Filtering Options**:
  - `start`: Start date for alert listing (format: "YYYY-MM-DD HH:MM:SS")
  - `end`: Optional end date for alert listing (format: "YYYY-MM-DD HH:MM:SS")
  - `id`: Find specific alert by ID
  - `assetName`: Filter by asset/hostname/endpoint name (substring match)
  - `assetId`: Filter by Asset ID (requires conversion from UUID using `assethandler_list_assets`)
  - `detectionProduct`: Filter by detection product:
    - `EDR`: Alerts from endpoint detection and response
    - `CWS`: Alerts from cloud workload security (K8s, containers)
    - `Identity`: Alerts from identity-related attacks (AD, domain reconnaissance)

### `casemanager_add_notes`
- **Purpose**: Add investigative notes to security alerts
- **Input**: List of dictionaries containing note text and alert IDs
- **Output**: Confirmation of applied notes
- **Required Fields**:
  - `text`: The note content to add to the alert
  - `alertId`: Unique alert ID (e.g., `0196d976-d1c5-7131-9013-c8176c12f930`)

## Endpoint Configuration

The CASEMANAGER Agent requires a webhook endpoint to be configured in the `AGENT_ENDPOINTS` dictionary:

```python
"CASEMANAGER_Agent": "https://your-domain.com/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>"
```

## Usage Examples

**List All Recent Alerts:**
```python
await casemanager_list_alerts([{}])
```

**Filter Alerts by Time Range:**
```python
await casemanager_list_alerts([{
    "start": "2025-04-10 00:00:00",
    "end": "2025-04-11 23:59:59"
}])
```

**Filter by Detection Product:**
```python
await casemanager_list_alerts([{"detectionProduct": "EDR"}])
```

**Filter by Asset Name:**
```python
await casemanager_list_alerts([{"assetName": "DESKTOP-ABC123"}])
```

**Add Notes to Alerts:**
```python
await casemanager_add_notes([
    {
        "text": "Initial triage completed - potential false positive",
        "alertId": "0196d976-d1c5-7131-9013-c8176c12f930"
    },
    {
        "text": "Escalated to SOC Level 2 for further analysis",
        "alertId": "0196d96f-1f7f-75c3-aa38-248f931ad924"
    }
])
```
