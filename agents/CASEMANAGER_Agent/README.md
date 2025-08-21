# CASEMANAGER Agent

## Agent Purpose

The CASEMANAGER Agent provides alert and case management capabilities. It enables security analysts to list, filter, and manage security alerts across different detection products, and add investigative notes to alerts for case documentation and collaboration.

## Capabilities/Functionalities Exposed

- **Alert Discovery**: List and filter security alerts with flexible time ranges
- **Advanced Filtering**: Filter by asset names, alert IDs, detection products, and time ranges
- **Note Management**: Add investigative notes to alerts for documentation and team collaboration

## Associated Tools

### `casemanager_list_alerts`
- **Purpose**: List and filter security alerts across all detection products
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
- **Required Fields**:
  - `text`: The note content to add to the alert
  - `alertId`: Unique alert ID (e.g., `0196d976-d1c5-7131-9013-c8176c12f930`)

## Endpoint Configuration

The CASEMANAGER Agent requires a webhook endpoint to be configured in the `AGENT_ENDPOINTS` dictionary in `server.py`:

```python
"CASEMANAGER_Agent": "https://your-domain.com/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>"
```

## Usage Examples

**List All Recent Alerts:**
```
list alerts in the last 10 days
```


```

**Filter by Detection Product:**
```
find identity alerts
```

**Filter by Asset Name:**
```python
await casemanager_list_alerts([{"assetName": "DESKTOP-ABC123"}])
```

**Add Notes to Alerts:**
```
add note to alert 019899bc-c050-781b-b1a3-0d09505ffe7d "this is an FP, believe me!"
```
