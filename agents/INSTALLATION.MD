# Agent Installation

There are three steps necessary to configure this architecture in HyperAutomation
1. Setting up the integrations
2. Uploading and activating the agents (workflows)
3. Updating the [API Endpoints in the MCP server](../server/server.py#L66-L71)

### Server Setup

####  Generating the Deployment Package

From the root of the project, run the command  `python configure_agents.py`

This will generate unique IDs for the agents and a deployment archive called `deployment_package.zip`

```python

📦 Creating zip archive: 'deployment_package.zip'...
🎉 Deployment package 'deployment_package.zip' is ready!
🧹 Cleaning up the 'deployment' directory...

--- UUID Assignment Summary ---
| Agent Name           | UUID                                 |
|---------------------|-------------------------------------|
| Asset Handler        | b64252f0-8921-43d0-a9f7-3727bdc70dc1 |
| Case Manager         | 07bc76d4-aed2-47ec-bf74-cdf5a52f8b42 |
| DB Manager           | c5e257f0-5a12-4213-a039-e28e3005dec4 |
| RO Manager           | 87ab6a11-ac6e-4691-ae45-e4c2cefb7edd |
| SDL                  | 8e015aa5-72b7-4cd4-946e-e190df8e568f |
| VT                   | 1bc6413b-5bbe-4a19-8ef5-6a494546136d |
---------------------------------------------------------
```

#### Upload the Agents

Once the ZIP file has been created. Log into the S1 management console and go to the HyperAutomation menu.
- Click Actions and Import 

<img width="446" height="628" alt="Image" src="https://github.com/user-attachments/assets/366bea70-f01a-481e-af96-f44024eca395" />

- Upload the archive `deployment_package.zip`


- Click on each of the newly created workflows and activate them

<img width="510" height="102" alt="Image" src="https://github.com/user-attachments/assets/b4ec1e65-49f4-4d2e-88f8-dfc6fa7d3ec9" />


### Client Setup
TODO

###
**Agent Endpoints:**
- Update all webhook URLs in `AGENT_ENDPOINTS` dictionary in [server.py](./server/server.py)
- Replace `<WEBHOOK_URI>` placeholders with actual webhook URIs from your SentinelOne environment
