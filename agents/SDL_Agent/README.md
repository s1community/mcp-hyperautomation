# SDL Agent

## Agent Purpose

The SDL (Singularity Data Lake) Agent should provide advanced query capabilities against the Singularity Data Lake using PowerQuery Language (PQL), enabling threat hunting and investigations across managed endpoints.

## Implemented Functionalities

- **PQL Query Execution**: Run PowerQuery Language queries against the Singularity Data Lake
- **Multi-Query Support**: Execute multiple queries in a single request
- **Flexible Time Range**: Support for custom time ranges with automatic 24-hour default
- **Advanced Pattern Matching**: Support for regex patterns with proper escaping
- **Natural Language to PQL conversion**: Support for automatic translation of natural language input into PQL syntax

## Associated Tools

### `sdl_run_query`
- **Purpose**: Execute one or multiple PQL queries against the Singularity Data Lake
- **Input**: PQL query with timeframe

### `pql_retrieve_knowledge`
- **Purpose**: Retrieve PQL syntax reference and example conversions
- **Usage**: Automatically called when the user asks wants to run a PQL query

### `get_remote_logons_for_endpoint`
- **Purpose**: Retrieve remote logons for a specific endpoint using internal PQL query
- **Input**: Endpoint hostname, start time, stop time
- **Output**: List of remote logon events with source IP, login types, and privilege information

### `get_remote_logon_patterns_for_username`
- **Purpose**: Generate login pattern summary for a specific user across all endpoints
- **Input**: Username, start time, stop time
- **Output**: High-level overview of user logon activity with success/failure breakdown

### `get_fuzzy_logon_session_windows`
- **Purpose**: Estimates start/end of logon sessions for a user or for all users on an endpoint
- **Input**: Time range, username and/or hostname
- **Output**: Correlated logon sessions with duration and privilege information

### `get_fuzzy_user_activity_windows`
- **Purpose**: Provide analysts with a timeframe (observation window) to use when investigating activity for a specific user on a system
- **Input**: Time range, username and/or hostname
- **Output**: Collapsed activity windows with timing estimates for further analysis

### `get_detailed_logons_for_username`
- **Purpose**: Retrieve the full list of local and remote logons for a specific user (username) across all managed endpoints
- **Input**: Username, start time, stop time
- **Output**: Comprehensive logon details across all managed endpoints

### `find_endpoint_hostname_from_ip`
- **Purpose**: Historical IP to hostname resolution for managed endpoints
- **Input**: IP address, start time, stop time
- **Output**: Endpoint information that historically used the specified IP

### `get_top_users_for_endpoints`
- **Purpose**: Identify most active users on specified endpoint(s)
- **Input**: hostname(s), start time, stop time
- **Output**: User activity frequency based on login and process creation events

### `get_detailed_process_list`
- **Purpose**: Retrieve detailed process creation events
- **Input**: Time range, optional username/hostname
- **Output**: Comprehensive process details including paths, command lines, and signatures

## Endpoint Configuration

The SDL Agent requires a webhook endpoint to be configured in the `AGENT_ENDPOINTS` dictionary in `server.py`:

```python
"SDL_Agent": "https://your-domain.com/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>"
```

## Usage Examples

**Run PQL Query:**
run this query filter( event.category == 'registry' AND registry.keyPath matches '\\\\Netlogon\\\\') | columns event.time, event.id, event.type, endpoint.name, agent.uuid, src.process.storyline.id, src.process.user, src.process.uid, src.process.cmdline, src.process.image.path, registry.keyUid, registry.keyPath, registry.value, registry.valueType for april 11 to 12 2025 and from April 1-3
```

**Natural Language to PQL conversion**
```
Show me incoming RDP connections from public IPs not in the US
```


**Remote Logon Analysis:**
```python
list remote logons for "DESKTOP-ABC123 on 2025-04-11
```
