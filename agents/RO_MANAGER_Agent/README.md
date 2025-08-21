# RO_MANAGER Agent

## Agent Purpose

The RO_MANAGER (Remote Operations Manager) Agent provides remote script execution and task management capabilities. It enables security analysts to discover available scripts in the library, execute remote operations tasks, and monitor task execution status across managed endpoints.

## Capabilities/Functionalities Exposed

- **Script Library Management**: List and discover available RemoteOps scripts
- **Task Execution Monitoring**: List and filter remote operations tasks/jobs
- **Historical Task Analysis**: Query task execution history with flexible filtering
- **Multi-Endpoint Support**: Monitor tasks across multiple endpoints simultaneously
- **Flexible Filtering**: Filter tasks by computer names, descriptions, and time ranges

## Associated Tools

### `ro_manager_list_scripts`
- **Purpose**: List all RemoteOps scripts available in the library
- **Input**: List with empty dictionary: `[{}]`
- **Output**: Complete inventory of available scripts for remote execution
- **Usage**: Discovery of available automation and investigation scripts

### `ro_manager_list_tasks`
- **Purpose**: List and filter RemoteOps tasks/jobs with comprehensive filtering options
- **Input**: List of condition dictionaries for filtering (use `[{}]` for all tasks)
- **Output**: Detailed task information including execution status, target endpoints, and descriptions
- **Filtering Options**:
  - `start`: Optional start date for task listing (format: "YYYY-MM-DD HH:MM:SS")
  - `end`: Optional end date for task listing (format: "YYYY-MM-DD HH:MM:SS")
  - `computerName__contains`: Filter tasks by target endpoint names (comma-separated list)
  - `description__contains`: Filter tasks by description keywords (comma-separated list)

## Endpoint Configuration

The RO_MANAGER Agent requires a webhook endpoint to be configured in the `AGENT_ENDPOINTS` dictionary:

```python
"RO_MANAGER_Agent": "https://your-domain.com/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>"
```

## Usage Examples

**List All Available Scripts:**
```python
await ro_manager_list_scripts([{}])
```

**List All Recent Tasks:**
```python
await ro_manager_list_tasks([{}])
```

**Filter Tasks by Target Endpoint:**
```python
await ro_manager_list_tasks([{
    "computerName__contains": "DESKTOP-ABC123,SERVER-XYZ"
}])
```

**Filter Tasks by Description Keywords:**
```python
await ro_manager_list_tasks([{
    "description__contains": "KAPE,YARA"
}])
```

**Filter Tasks by Time Range:**
```python
await ro_manager_list_tasks([{
    "start": "2025-04-10 00:00:00",
    "end": "2025-04-11 23:59:59"
}])
```

**Combined Filtering:**
```python
await ro_manager_list_tasks([{
    "start": "2025-04-10 00:00:00",
    "computerName__contains": "WORKSTATION-001",
    "description__contains": "forensics"
}])
```
