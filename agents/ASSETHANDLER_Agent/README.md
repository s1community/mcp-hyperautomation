# ASSETHANDLER Agent

## Agent Purpose

The ASSETHANDLER Agent should enable the discovery of endpoints connected to the management console, including detailed asset information retrieval and agent configuration retrieval.

## Implemented Functionalities

- **Endpoint Discovery**: List and filter endpoints based on various criteria
- **Configuration Retrieval**: Access detailed agent/endpoint configuration settings
- **Advanced Filtering**: Support for complex filtering conditions with boolean AND logic
- **IP Address Analysis**: Search by internal and external IP addresses
- **Threat Status Monitoring**: Filter by active threats and infection status

## Associated Tools

### `assethandler_list_endpoints`
- **Purpose**: List/find asset endpoints with optional filtering
- **Input**: List of condition dictionaries for filtering (use `[{}]` for all endpoints)
- **Output**: Comprehensive endpoint information including network details, threat status, and system information
- **Filtering Options**:
  - `filteredSiteIds`: Filter by Site IDs
  - `networkInterfaceInet__contains`: Filter by local IP addresses
  - `externalIp__contains`: Filter by external IP addresses
  - `computerName__contains`: Filter by computer names
  - `activeThreats__gt`: Filter by minimum active threats
  - `infected`: Filter by infection status
  - `osTypes`: Filter by operating system type
  - `query`: Free-text search across applicable attributes

### `assethandler_list_assets`
- **Purpose**: Obtain Endpoint Asset ID from Endpoint UUID (UUID to Asset ID conversion)
- **Input**: List of condition dictionaries with `agentUuid` parameter
- **Output**: Asset information including the critical Asset ID mapping
- **Primary Use Case**: Convert endpoint UUID (e.g., `927088eb-b890-4e7e-ba26-ebdc8f77f5a7`) to Asset ID (e.g., `5qyrgexenze4znwm6iihjd5weq`)

### `assethandler_get_agents_config`
- **Purpose**: Retrieve agent/endpoint configuration for one or multiple endpoints
- **Input**: List of condition dictionaries for filtering (use `[{}]` for all endpoints)
- **Output**: Detailed configuration settings for the specified endpoints
- **Filtering Options**:
  - `computerName__contains`: Filter by computer names

## Endpoint Configuration

The ASSETHANDLER Agent requires a webhook endpoint to be configured in the `AGENT_ENDPOINTS` dictionary in `server.py`:

```python
"ASSETHANDLER_Agent": "https://your-domain.com/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>"
```

## Usage Examples

**List All Endpoints:**
```
list endpoints
```

**Filter by IP Address:**
```python
Find asset with ip 192.168.1.100
```

**Get Configuration for Specific Endpoints:**
```
pull agent config for Frontier-PHX	
```
