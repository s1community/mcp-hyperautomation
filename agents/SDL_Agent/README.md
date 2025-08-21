# SDL Agent

## Agent Purpose

The SDL (Singularity Data Lake) Agent provides advanced query capabilities against the Singularity Data Lake using PowerQuery Language (PQL). It enables comprehensive security data analysis, threat hunting, and forensic investigations across managed endpoints.

## Capabilities/Functionalities Exposed

- **PQL Query Execution**: Run complex PowerQuery Language queries against the Singularity Data Lake
- **Multi-Query Support**: Execute multiple queries in a single request
- **Flexible Time Range**: Support for custom time ranges with automatic 24-hour default
- **Advanced Pattern Matching**: Support for regex patterns with proper escaping
- **Knowledge Base Integration**: Access to PQL syntax reference and example conversions

## Associated Tools

### `sdl_run_query`
- **Purpose**: Execute one or multiple PQL queries against the Singularity Data Lake
- **Input**: List of query dictionaries containing start time, stop time, and PQL query
- **Output**: Query results with detailed event data in ascending time order
- **Special Handling**: Automatic backslash escaping for "matches" conditions (requires 8 backslashes)
- **Presentation**: Results formatted in markdown table with time, endpoint, and event details

### `pql_retrieve_knowledge`
- **Purpose**: Retrieve PQL syntax reference and example conversions
- **Input**: Empty dictionary list: `[{}]`
- **Output**: Comprehensive prompt engineering guidance and syntax reference
- **Usage**: Called once per session to provide context for query generation

### `get_remote_logons_for_endpoint`
- **Purpose**: Retrieve remote logons for a specific endpoint using internal PQL query
- **Input**: Endpoint hostname, start time, stop time
- **Output**: List of remote logon events with source IP, login types, and privilege information

### `get_remote_logon_patterns_for_username`
- **Purpose**: Generate logon pattern summary for a specific user across all endpoints
- **Input**: Username, start time, stop time
- **Output**: High-level overview of user logon activity with success/failure breakdown

### `get_fuzzy_logon_session_windows`
- **Purpose**: Correlate login/logout events to rebuild logon sessions
- **Input**: Time range, optional username/hostname
- **Output**: Correlated logon sessions with duration and privilege information

### `get_fuzzy_user_activity_windows`
- **Purpose**: Provide observation windows for investigative purposes
- **Input**: Time range, optional username/hostname
- **Output**: Collapsed activity windows with timing estimates for further analysis

### `get_detailed_logons_for_username`
- **Purpose**: Retrieve complete list of local and remote logons for a user
- **Input**: Username, start time, stop time
- **Output**: Comprehensive logon details across all managed endpoints

### `find_endpoint_hostname_from_ip`
- **Purpose**: Historical IP to hostname resolution for managed endpoints
- **Input**: IP address, start time, stop time
- **Output**: Endpoint information that historically used the specified IP

### `get_top_users_for_endpoints`
- **Purpose**: Identify most active users on specified endpoints
- **Input**: List of hostnames, start time, stop time
- **Output**: User activity frequency based on login and process creation events

### `get_detailed_process_list`
- **Purpose**: Retrieve detailed process creation events
- **Input**: Time range, optional username/hostname
- **Output**: Comprehensive process details including paths, command lines, and signatures

## Endpoint Configuration

The SDL Agent requires a webhook endpoint to be configured in the `AGENT_ENDPOINTS` dictionary:

```python
"SDL_Agent": "https://your-domain.com/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>"
```

## Usage Examples

**Basic PQL Query:**
```python
await sdl_run_query([{
    "start": "2025-04-11 00:00:00",
    "stop": "2025-04-12 00:00:00", 
    "query": "event.category='registry' registry.keyPath matches '.*\\\\\\\\\\\\\\\\Netlogon\\\\\\\\\\\\\\\\.*'"
}])
```

**Remote Logon Analysis:**
```python
await get_remote_logons_for_endpoint("DESKTOP-ABC123", "2025-04-11 00:00:00", "2025-04-12 00:00:00")
```
