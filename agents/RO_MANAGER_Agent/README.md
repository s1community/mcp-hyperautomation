# RO_MANAGER Agent

## Agent Purpose

The RO_MANAGER (Remote Operations Manager) Agent should provides task management capabilities in RemoteOps. Analysts should be able to discover available scripts in the library, execute remote operations tasks, and monitor task execution status across managed endpoints.

## Implemented Functionalities

- **Script Library Management**: List and discover available RemoteOps scripts
- **Task Execution Monitoring**: List and filter remote operations tasks/jobs

## Associated Tools

### `ro_manager_list_scripts`
- **Purpose**: List all RemoteOps scripts available in the library
- **Output**: Complete inventory of available scripts for remote execution

### `ro_manager_list_tasks`
- **Purpose**: List and filter RemoteOps tasks/jobs with comprehensive filtering options
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
list remoteops scripts
```

**List All Recent Tasks:**
```
list remoteops tasks
```

**Filter Tasks by Target Endpoint:**
```
list remote ops tasks for DESKTOP-ABC123
```

**Filter Tasks by Description Keywords:**
```
list ro tasks associated with KAPE
```

**Filter Tasks by Time Range and Endpoint:**
```
show me the remotops tasks for the last 10 days for the system WORKSTATION-001
```

