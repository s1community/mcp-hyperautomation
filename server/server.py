#!/usr/bin/env python3
"""
MCP (Model Context Protocol) Server

This server acts as a bridge between the LLM  client and remote services.
It implements the MCP protocol to allow LLM Clients to use tools/functions like ti_lookup.

Current implemented tools:
- ti_lookup: Threat intelligence lookup for IPs, FQDNs, and hashes
- sdl_run_query: Run one or multiple PQL queries against the Singularity Data Lake and collect the results
- list_endpoints: List endpoints connected to the management console. Optionally filter by conditions
"""

import os
import uuid
import logging
import requests
import sys
import argparse
import inspect
import asyncio
import json
from typing import Dict, List, Any, Optional
from textwrap import dedent

from mcp.server.fastmcp import FastMCP, Context
from utils.db_manager import DB_Manager
from utils.PQL_XLS_Reader import PQL_XLS_Reader
from utils.fuzzy_logons import correlate_login_logout, collapse_orphans, generate_activity_summary

# --- Configure Logging ---
logger = logging.getLogger("mcp-server")
# Set the minimum logging level for the logger (as per your original)
logger.setLevel(logging.DEBUG)

LOG_FILE_PATH = os.getenv("MCP_SERVER_LOG_FILE", "mcp_server.log")
# Create a formatter (as per your original)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create a handler to write logs to a file (as per your original)
file_handler = logging.FileHandler(LOG_FILE_PATH)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

# Create a handler to write logs to standard error (console) (as per your original)
console_handler = logging.StreamHandler(sys.stderr)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)

# Add the handlers to the logger (as per your original)
if not logger.handlers:
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


# Common DB polling parameters
DB_POLLING_MAX_RETRIES = int(os.getenv("DB_MAX_RETRIES", 200))
DB_POLLING_RETRY_DELAY = int(os.getenv("DB_RETRY_DELAY", 1))

# DB_Manager specific configuration
DB_SERVICE_TYPE = os.getenv("DB_SERVICE_TYPE", "bigquery").lower() #"bigquery" or "gsheet"

CREDENTIALS_FILE_PATH = os.getenv("CREDENTIALS_FILE", "/PATH_TO_CREDENTIALS_FILE/CREDENTIALS_FILE_NAME.json")


AGENT_ENDPOINTS = {
    "VT_Agent" : "https://<CONSOLE_NAME>.sentinelone.net/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>",
    "SDL_Agent" : "https://<CONSOLE_NAME>.sentinelone.net/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>",
    "ASSETHANDLER_Agent" : "https://<CONSOLE_NAME>.sentinelone.net/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>",
    "CASEMANAGER_Agent" : "https://<CONSOLE_NAME>.sentinelone.net/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>",
    "RO_MANAGER_Agent" :  "https://<CONSOLE_NAME>.sentinelone.net/web/api/v2.1/hyper-automate/webhook/v1/webhook/http/<WEBHOOK_URI>"
}

# --- Initialize DB Manager ---
db_manager_instance: Optional[DB_Manager] = None
if CREDENTIALS_FILE_PATH:
    try:
        db_manager_instance = DB_Manager(
            service_type=DB_SERVICE_TYPE,
            credentials_path=CREDENTIALS_FILE_PATH, # Pass the path hint
            default_max_retries=DB_POLLING_MAX_RETRIES,
            default_retry_delay=DB_POLLING_RETRY_DELAY
        )
        logger.info(f"DB_Manager initialized successfully for service: {DB_SERVICE_TYPE}")
    except FileNotFoundError as fnf_error: # From DB_Manager or its clients
        logger.error(f"DB_Manager init error: Credentials file issue - {fnf_error}. Path used: '{CREDENTIALS_FILE_PATH}'", exc_info=False)
    except ValueError as val_error: # From DB_Manager for missing configs like GOOGLE_SHEET_ID
        logger.error(f"DB_Manager init error: Configuration value error - {val_error}", exc_info=False)
    except Exception as e:
        logger.error(f"DB_Manager: Failed to initialize during server startup - {e}", exc_info=True)
else:
    logger.critical("CREDENTIALS_FILE environment variable not set or path is empty. DB_Manager cannot be initialized. DB-dependent tools will fail.")


# --- Create FastMCP server ---
mcp = FastMCP("Interactive-Security-Orchestrator")

# --- Helper Functions ---
def send_webhook_request(endpoint: str, action: str, input_data: List[Any]) -> Dict[str, Any]:
    # This function is exactly as in your original mcp_server.py
    req_id = str(uuid.uuid4())
    payload = {
        "req_id": req_id,
        "action": action,
        "input": input_data
    }
    logger.debug(f"Sending {action} request with req_id: {req_id} to {endpoint}")
    try:
        response = requests.post(
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        response.raise_for_status()
        response_data = response.json()
        logger.debug(f"Webhook response for req_id {req_id}: {response_data}")
        # Assuming the webhook itself doesn't return a different req_id for polling
        # and status is implicitly "initiated" on success.
        return {"status": "initiated", "req_id": req_id}
    except requests.RequestException as e:
        logger.error(f"Failed to send webhook request for action {action} (req_id: {req_id}): {e}")
        return {"status": "error", "message": f"Failed to contact webhook for action {action}: {str(e)}"}
    except json.JSONDecodeError as e: # Added for robustness
        logger.error(f"Webhook response for action '{action}' was not valid JSON (req_id: {req_id}): {e}")
        return {"status": "error", "message": f"Webhook for '{action}' gave invalid JSON response."}


async def retrieve_results_for_request(req_id: str, expected_row_number: int = 1, **client_kwargs) -> Dict[str, Any]:
    """
    Polls the Database (via DB_Manager) for results matching the req_id.
    """
    if not db_manager_instance:
        logger.error(f"DB_Manager is not initialized. Cannot retrieve results for req_id: {req_id}.")
        return {"status": "error", "req_id": req_id, "message": "Database manager is not initialized"}

    # The **client_kwargs could be used if a specific tool needs to override, e.g.,
    # the sheet_name for a GSheet call: sheet_name_override="special_sheet"
    return await db_manager_instance.retrieve_results_from_db(
        req_id=req_id,
        expected_row_number=expected_row_number,
        
        **client_kwargs
    )


# --- MCP Tools defined with @mcp.tool() ---
# Need to ensure the synchronous calls within these async tools use asyncio.to_thread
@mcp.tool()
async def vt_ti_lookup(indicators: List[str]) -> Dict[str, Any]:
    """
    Perform threat intelligence lookup (via Virus Total) on multiple host-based indicators (HBIs) and network-based indicators (NBIs) including: IPs, FQDNs and hashes.
    Provides information on reputation, classification, and other security details.

    :param indicators: List of indicators to lookup. Can include IPs, FQDNs, and hashes (MD5, SHA-1, SHA-256). Example: ['8.8.8.8', 'google.com', 'hash']
    :return: Dictionary containing the status and results

    PRESENTATION HINT:
    Present the results in a well-formatted markdown table with columns for
    "Indicator, Type, Classification, Risk Score, Detections, and First/Last Seen dates. For each row"
     "use bold text for high-risk indicators (score >= 7).
     SHOW ALL RESULTS
    """
    logger.info(f"MCP Tool: vt_ti_lookup called with indicators: {indicators}")
    agent_name = "_".join([inspect.currentframe().f_code.co_name.split("_")[0].upper(),"Agent"])

    endpoint = AGENT_ENDPOINTS.get(agent_name)
    if not endpoint:
        err_msg = f"Tool endpoint configuration for '{agent_name}' is missing"
        logger.error(err_msg)
        # MCP tools should return a serializable result, error status included
        return {"status": "error", "message": err_msg}

    # Use asyncio.to_thread for the synchronous requests.post call
    webhook_result = await asyncio.to_thread(send_webhook_request, endpoint=endpoint, action="ti_lookup", input_data=indicators)

    if webhook_result["status"] == "initiated":
        req_id = webhook_result["req_id"]
        logger.debug(f"vt_ti_lookup: Webhook initiated, waiting for results for req_id: {req_id}.")
        # await the async wait_for_results
        results = await retrieve_results_for_request(req_id)
        return results
    else:
        logger.error(f"vt_ti_lookup: Webhook request failed: {webhook_result.get('message')}")
        return webhook_result


@mcp.tool()
async def sdl_run_query(queries: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    ALWAYS retrieve the PQL/PowerQuery knowledge base before generating or validating any PQL queries, unless it is already present in our conversation context.
    Run one or multiple PQL queries against the Singularity Data Lake. Each query will be expliclity provided by the user using the PQL
    syntax.
    Only invoke this tools if the use wants to directly run a query. If the user only wants to create or write a query, do not run this tool, wait for confirmation from the user first.
    If the query uses the condition "matches" then the number of backslashes MUST BE 8 (before and after the term) (E.g  "query":
    "event.category='registry' registry.keyPath matches '.*\\\\\\\\\\\\\\\\Netlogon\\\\\\\\\\\\\\\\.*'").
    If the user specified less than 8, you MUST rewrite the query to add a total of 8 backslaskhes "\" before and after the term as per
    the examples (E.g matches '.*\\AppData\\.*'  -> matches '.*\\\\\\\\\\\\\\\\AppData\\\\\\\\\\\\\\\\.*'
    :param queries: List of user-provided queries written in PQL including a START and STOP time for the timeframe in the format
    "YYYY-MM-DD HH:MM:SS".
    If the use does not specify the timeframe, you **MUST** immediately run the query and use the last 24 hours (midnight to midnight)
    as timeframe automatically. Example of query:
    [
      {
       "start": "2025-04-11 00:00:00",
       "stop":"2025-04-12 00:00:00",
       "query": "event.category='registry' registry.keyPath matches '.*\\\\\\\\Netlogon\\\\\\\\.*'"
      }
    ]
    :return: List of dictionaries, each containing the Input query (including the timeframe), the results as a list of rows ("pql_rows")
    and the field "errors" which is populated in case of server-side error.
    An error usually indicates a problem in the synatx of the input query.
    PRESENTATION HINT:
    Present the results in a well-formatted markdown table with columns for each of the fields included in the results rows (e.g
    event.time, src.process.name, etc) starting always with the time, endpoint,name and event type first.
    Resuls should be in ASCending order by event.time
    """
    logger.info(f"MCP Tool: sdl_run_query called with input: {queries}")
    queries_count = len(queries)
    agent_name = "_".join([inspect.currentframe().f_code.co_name.split("_")[0].upper(),"Agent"])

    endpoint = AGENT_ENDPOINTS.get(agent_name)
    if not endpoint:
        err_msg = f"Tool endpoint configuration for '{agent_name}' is missing"
        logger.error(err_msg)
        return {"status": "error", "message": err_msg}

    # Use asyncio.to_thread for the synchronous requests.post call
    webhook_result = await asyncio.to_thread(send_webhook_request, endpoint=endpoint, action="execute_pql_query", input_data=queries)

    if webhook_result["status"] == "initiated":
        req_id = webhook_result["req_id"]
        logger.debug(f"sdl_run_query: Webhook initiated, waiting for results for req_id: {req_id}. Expecting {queries_count} rows.")
        # await the async wait_for_results
        results = await retrieve_results_for_request(req_id,expected_row_number=queries_count)
        return results
    else:
        logger.error(f"sdl_run_query: Webhook request failed: {webhook_result.get('message')}")
        return webhook_result


@mcp.tool()
async def assethandler_list_endpoints(conditions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    List/Find asset endpoints.
    To filter, ALWAYS provide a list of condition dictionaries. To list all endpoints without filters, the 'conditions' argument MUST be a list with an empty dictionary: [{}].
    Conditions are automatically applied in BOOLEAN AND in the backend.
    If the user wants to apply conditions in BOOLEAN OR, multiple distinct requests (calls to this tool) need to be made.
    Example for filtering: [{"networkInterfaceInet__contains": "192.168.192.20"}]
    Example of LISTING ALL ENDPOINTS  (no filters): [{}]

    :param conditions: A LIST that is either:
                            1. A list with a single empty dictionary `[{}]` (to list/find all endpoints).
                            2. A list of dictionaries for filtering.
    :return: Dictionary containing endpoint information or an error.

    When creating the filters, ONLY use the conditions listed below.
    NEVER guess the condition and ONLY use the conditions listed below.
    Using a condition not included in the list below will cause an error.
    Some conditions support a list of COMMA-separated values (string []) (E.g "value1,value")
    If the user requests to filter by a condition whose name is not listed below or unknown, use the generic filter 'query'
    When the user wants to search by IP address, be comprehensive and use all possible criteria that are relevant for IP addresses (multiple distinct requests if necessary)
    - filteredSiteIds: (string []) List of Site IDs to filter by. Example: "225494730938493804,225494730938493915".
    - networkInterfaceInet__contains: (string []) Free-text filter by local IP (supports multiple values)
    - externalIp__contains: (string []) Include agents with these external IP address (Example "200.138.151.22,73.11.11.45")
    - accountIds: (string []) List of Account IDs to filter by
    - activeThreats__gt: (integer) Include Agents with at least this amount of active threats
    - activeThreats: (integer) Include Agents with this amount of active threats
    - infected: (boolean) Include Agents that are infected. Example: true
    - computerName__contains: Free-text filter by computer name (supports multiple values). Example: "john-office,WIN-XX"

    """
    logger.info(f"MCP Tool: asset_list_endpoints called with conditions: {conditions}")
    agent_name = "_".join([inspect.currentframe().f_code.co_name.split("_")[0].upper(),"Agent"])

    endpoint = AGENT_ENDPOINTS.get(agent_name)
    if not endpoint:
        err_msg = f"Tool endpoint configuration for '{agent_name}' is missing"
        logger.error(err_msg)
        return {"status": "error", "message": err_msg}

    # Use asyncio.to_thread for the synchronous requests.post call
    webhook_result = await asyncio.to_thread(send_webhook_request, endpoint=endpoint, action="list_endpoints", input_data=conditions)


    if webhook_result["status"] == "initiated":
        req_id = webhook_result["req_id"]
        logger.debug(f"asset_list_endpoints: Webhook initiated, waiting for results for req_id: {req_id}.")
        # await the async wait_for_results
        results = await retrieve_results_for_request(req_id)
        return results
    else:
        logger.error(f"asset_list_endpoints: Webhook request failed: {webhook_result.get('message')}")
        return webhook_result


@mcp.tool()
async def assethandler_list_assets(conditions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    List/Find assets. This is a secondary API endpoint that SHOULD ONLY be used to obtain the Endpoint "Asset ID" (E.g "id": "5qyrgexenze4znwm6iihjd5weq") by knowing the Endpoint UUID (E.g 927088eb-b890-4e7e-ba26-ebdc8f77f5a7)
    To filter, ALWAYS provide a list of condition dictionaries. To list all endpoints without filters, the 'conditions' argument MUST be a list with an empty dictionary: [{}].
    Conditions are automatically applied in BOOLEAN AND in the backend.
    If the user wants to apply conditions in BOOLEAN OR, multiple distinct requests (calls to this tool) need to be made.
    Example for filtering: [{'agentUuid': '927088eb-b890-4e7e-ba26-ebdc8f77f5a7,648f92e1-a8b9-4247-9fb4-a380fb931904'}]
    Example of LISTING ALL ENDPOINTS  (no filters): [{}]

    :param conditions: A LIST that is either:
                            1. A list with a single empty dictionary `[{}]` (to list/find all endpoints).
                            2. A list of dictionaries for filtering.
    :return: Dictionary containing endpoint information or an error. This method MUST BE CALLED to pivot from endpoint UUID (from "927088eb-b890-4e7e-ba26-ebdc8f77f5a7" to "5qyrgexenze4znwm6iihjd5weq")
    When creating the filters, ONLY use the conditions listed below.
    NEVER guess the condition and ONLY use the conditions listed below.
    Using a condition not included in the list below will cause an error.
    Some conditions support a list of COMMA-separated values (string []) (E.g "value1,value")
    - agentUuid: (string []) List of Agent UUIDs to filter by. Example: "927088eb-b890-4e7e-ba26-ebdc8f77f5a7,648f92e1-a8b9-4247-9fb4-a380fb931904"
    """
    logger.info(f"MCP Tool: asset_list_assets called with conditions: {conditions}")
    agent_name = "_".join([inspect.currentframe().f_code.co_name.split("_")[0].upper(),"Agent"])

    endpoint = AGENT_ENDPOINTS.get(agent_name)
    if not endpoint:
        err_msg = f"Tool endpoint configuration for '{agent_name}' is missing"
        logger.error(err_msg)
        return {"status": "error", "message": err_msg}

    # Use asyncio.to_thread for the synchronous requests.post call
    webhook_result = await asyncio.to_thread(send_webhook_request, endpoint=endpoint, action="list_assets", input_data=conditions)


    if webhook_result["status"] == "initiated":
        req_id = webhook_result["req_id"]
        logger.debug(f"asset_list_endpoints: Webhook initiated, waiting for results for req_id: {req_id}.")
        # await the async wait_for_results
        results = await retrieve_results_for_request(req_id)
        return results
    else:
        logger.error(f"asset_list_endpoints: Webhook request failed: {webhook_result.get('message')}")
        return webhook_result


@mcp.tool()
async def assethandler_get_agents_config(conditions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get Agent/Endpoint Configuration for one or multiple endpoints.
    To filter, ALWAYS provide a list of condition dictionaries. To list all endpoints without filters, the 'conditions' argument MUST be a list with an empty dictionary: [{}].
    Example for selective Endpoints: [{"computerName__contains": "john-laptop,DESKTOP-XXJ1U391"}]
    Example of retrieving config for ALL ENDPOINTS  (no filters): [{}]

    :param conditions: A LIST that is either:
                            1. A list with a single empty dictionary `[{}]` (to get the config for all endpoints).
                            2. A list of dictionaries for filtering.
    :return: Dictionary containing endpoint config

    When creating the filters, ONLY use the conditions listed below.
    NEVER guess the condition and ONLY use the conditions listed below.
    Using a condition not included in the list below will cause an error.
    - computerName__contains: Free-text filter by computer name (supports multiple values). Example: "john-office,WIN-XX"

    """
    logger.info(f"MCP Tool: assethandler_get_agents_config called with conditions: {conditions}")
    agent_name = "_".join([inspect.currentframe().f_code.co_name.split("_")[0].upper(),"Agent"])

    endpoint = AGENT_ENDPOINTS.get(agent_name)
    if not endpoint:
        err_msg = f"Tool endpoint configuration for '{agent_name}' is missing"
        logger.error(err_msg)
        return {"status": "error", "message": err_msg}

    # Use asyncio.to_thread for the synchronous requests.post call
    webhook_result = await asyncio.to_thread(send_webhook_request, endpoint=endpoint, action="get_agents_config", input_data=conditions)


    if webhook_result["status"] == "initiated":
        req_id = webhook_result["req_id"]
        logger.debug(f"assethandler_get_agents_config: Webhook initiated, waiting for results for req_id: {req_id}.")
        # await the async wait_for_results
        results = await retrieve_results_for_request(req_id)
        return results
    else:
        logger.error(f"assethandler_get_agents_config: Webhook request failed: {webhook_result.get('message')}")
        return webhook_result


@mcp.tool()
async def casemanager_list_alerts(conditions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    List Alerts.To filter, ALWAYS provide a list of condition dictionaries. To list all alerts without filters, the 'conditions' argument MUST be a list with an empty dictionary: [{}].
    Conditions are automatically applied in BOOLEAN AND in the backend.
    If the user wants to apply conditions in BOOLEAN OR, multiple distinct requests (calls to this tool) need to be made.
    Example for filtering: [{"assetName": "Frontier-PHX"}]
    Example of LISTING ALL ALERTS  (no filters): [{}]

    :param conditions: A LIST that is either:
                            1. A list with a single empty dictionary `[{}]` (to list ALL alerts in the last 3 months).
                            2. A list of dictionaries for filtering.
    :return: Dictionary containing Alerts or an error.

    When creating the filters, ONLY use the conditions listed below.
    NEVER guess the condition and ONLY use the conditions listed below.
    Using a condition not included in the list below will cause an error.
    - start: (string) Start date in the format "YYYY-MM-DD HH:MM:SS" for listing Alerts (This will return alerts newer than the date specified)
    - end: (string) [Optional] End date in the format "YYYY-MM-DD HH:MM:SS" for listing Alerts up to the specified date. This is optional and if omitted, all results newer than "start" will be returned.
    - id: (string) Find Alert by its ID (single value, no list)
    - assetName: (string) Find Alerts where the impacted  asset/hostname/endpoint contains the substring <assetName> (E.g "DC-")
    - assetId: (string) Find Alerts for the asset whose "Asset ID" matches the provided value (single value, no list). The "Asset ID" can ONLY BE FOUND by invoking the function  "assethandler_list_assets" with the asset UUID (from "927088eb-b890-4e7e-ba26-ebdc8f77f5a7" to "5qyrgexenze4znwm6iihjd5weq")
    - detectionProduct (string): Only use this condition to explicitly  alerts by the product that has generated them. Supported Values include the following:
        - EDR: Alert coming from the EDR/EPP solution (agent running on the endpoint)
        - CWS: Alert coming from a cloud assets (e.g K8 workload)
        - Identity: Alert associated with Identity-related attacks (AD-based priv escalation, Domain-reconnaissance, etc)

    """
    logger.info(f"MCP Tool: asset_list_assets called with conditions: {conditions}")
    agent_name = "_".join([inspect.currentframe().f_code.co_name.split("_")[0].upper(),"Agent"])

    endpoint = AGENT_ENDPOINTS.get(agent_name)
    if not endpoint:
        err_msg = f"Tool endpoint configuration for '{agent_name}' is missing"
        logger.error(err_msg)
        return {"status": "error", "message": err_msg}

    # Use asyncio.to_thread for the synchronous requests.post call
    webhook_result = await asyncio.to_thread(send_webhook_request, endpoint=endpoint, action="list_alerts", input_data=conditions)


    if webhook_result["status"] == "initiated":
        req_id = webhook_result["req_id"]
        logger.debug(f"asset_list_endpoints: Webhook initiated, waiting for results for req_id: {req_id}.")
        # await the async wait_for_results
        results = await retrieve_results_for_request(req_id)
        return results
    else:
        logger.error(f"asset_list_endpoints: Webhook request failed: {webhook_result.get('message')}")
        return webhook_result


@mcp.tool()
async def casemanager_add_notes(notes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Add Notes to Alerts.To add notes, ALWAYS provide a list of dictionaries, each containing the text to be added as a note and the alertId of the alert to be updated.
    Example for filtering: [{"assetName": "Frontier-PHX"}]
    Example: [{'text': 'This is a note sent by Maestro', 'alertId': '0196d976-d1c5-7131-9013-c8176c12f930'}, {'text': 'Alert triaged. FP', 'alertId': '0196d96f-1f7f-75c3-aa38-248f931ad924'}]

    :param notes: A LIST of dictionaries, each containing both the key 'text' and 'alertId'
    :return: Dictionary containing information on the applied Notes.

    When creating the notes, ONLY use the fields listed below.
    Using a field not included in the list below will cause an error.
    - text: (string) This is the note to be added to the alert
    - alertID: (string) Unique ID of an alert  (e.g 0196d976-d1c5-7131-9013-c8176c12f930) to identify the Alert to which the note will be applied
    """
    logger.info(f"MCP Tool: casemanager_add_notes called with conditions: {notes}")
    agent_name = "_".join([inspect.currentframe().f_code.co_name.split("_")[0].upper(),"Agent"])

    endpoint = AGENT_ENDPOINTS.get(agent_name)
    if not endpoint:
        err_msg = f"Tool endpoint configuration for '{agent_name}' is missing"
        logger.error(err_msg)
        return {"status": "error", "message": err_msg}

    # Use asyncio.to_thread for the synchronous requests.post call
    webhook_result = await asyncio.to_thread(send_webhook_request, endpoint=endpoint, action="add_notes", input_data=notes)


    if webhook_result["status"] == "initiated":
        req_id = webhook_result["req_id"]
        logger.debug(f"asset_list_endpoints: Webhook initiated, waiting for results for req_id: {req_id}.")
        # await the async wait_for_results
        results = await retrieve_results_for_request(req_id)
        return results
    else:
        logger.error(f"asset_list_endpoints: Webhook request failed: {webhook_result.get('message')}")
        return webhook_result

@mcp.tool()
async def pql_retrieve_knowledge(context:List) -> str:
    """
    ALWAYS provide a list of context dictionaries. The list MUST contain a single EMPTY dictionary: [{}].
    This tool returns prompt-engineering guidance, including syntax reference and example conversions from natural language to query format (PowerQuery).
    You should only call this tool ONCE per session, and only if no such guidance is already available in the current context window.
    If the data has been retrieved earlier and is still accessible in context, reuse it and do not call this tool again.

    :param context: An empty dictionary: {}
    :return: A large prompt string.
    """
    with open("resources/NL2PQL_prompt.txt", "r", encoding="utf-8") as f:
        pql_prompt = f.read()

    return pql_prompt


@mcp.tool()
async def ro_manager_list_scripts(conditions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    List RemoteOps Scripts. To list all remoteOps scripts in the Library, the 'conditions' argument MUST be a list with an empty dictionary: [{}].
    Conditions are automatically applied in BOOLEAN AND in the backend.
    Example of LISTING ALL SCRIPTS  (no filters): [{}]

    :param conditions: A LIST with a single empty dictionary `[{}]`
    :return: Dictionary containing scripts in the library or an error.

    """
    logger.info(f"MCP Tool: {inspect.currentframe().f_code.co_name} called with conditions: {conditions}")
    agent_name = "_".join(inspect.currentframe().f_code.co_name.split("_")[:2]).upper() + "_Agent"


    endpoint = AGENT_ENDPOINTS.get(agent_name)
    if not endpoint:
        err_msg = f"Tool endpoint configuration for '{agent_name}' is missing"
        logger.error(err_msg)
        return {"status": "error", "message": err_msg}

    # Use asyncio.to_thread for the synchronous requests.post call
    webhook_result = await asyncio.to_thread(send_webhook_request, endpoint=endpoint, action="list_scripts", input_data=conditions)


    if webhook_result["status"] == "initiated":
        req_id = webhook_result["req_id"]
        logger.debug(f"{inspect.currentframe().f_code.co_name}: Webhook initiated, waiting for results for req_id: {req_id}.")
        # await the async wait_for_results
        results = await retrieve_results_for_request(req_id)
        return results
    else:
        logger.error(f"{inspect.currentframe().f_code.co_name}: Webhook request failed: {webhook_result.get('message')}")
        return webhook_result

@mcp.tool()
async def ro_manager_list_tasks(conditions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    List Tasks (includes RemoteOps tasks/jobs).To filter, ALWAYS provide a list of condition dictionaries. To list all tasks without filters, the 'conditions' argument MUST be a list with an empty dictionary: [{}].
    Conditions are automatically applied in BOOLEAN AND in the backend.
    If the user wants to apply conditions in BOOLEAN OR, multiple distinct requests (calls to this tool) need to be made.
    Example for filtering: [{"computerName__contains": "Frontier-PHX"}]
    Example of LISTING ALL RemoteOPs TASKS  (no filters): [{}]

    :param conditions: A LIST that is either:
                            1. A list with a single empty dictionary `[{}]` (to list ALL Tasks in the last months).
                            2. A list of dictionaries for filtering.
    :return: Dictionary containing RO Tasks or an error.

    When creating the filters, ONLY use the conditions listed below.
    NEVER guess the condition and ONLY use the conditions listed below.
    Using a condition not included in the list below will cause an error.
    - start: (string)[Optional] Start date in the format "YYYY-MM-DD HH:MM:SS" for listing Tasks (This will return alerts newer than the date specified) This is optional
    - end: (string) [Optional] End date in the format "YYYY-MM-DD HH:MM:SS" for listing Tasks up to the specified date. This is optional
    - computerName__contains: (string)[Optional] List Tasks targeting the endpoint(s) in the list  (E.g "computerName__contains": "Frontier-PHX","LAPTOP-847172K,DESKTOP-MULLAH") This is optional
    - description__contains: (string) [Optional] List Tasks whose description/name contain one of the words in the list (E.g  "description__contains": "KAPE","YARA") This is optional

    """
    logger.info(f"MCP Tool: {inspect.currentframe().f_code.co_name} called with conditions: {conditions}")
    agent_name = "_".join(inspect.currentframe().f_code.co_name.split("_")[:2]).upper() + "_Agent"

    endpoint = AGENT_ENDPOINTS.get(agent_name)
    if not endpoint:
        err_msg = f"Tool endpoint configuration for '{agent_name}' is missing"
        logger.error(err_msg)
        return {"status": "error", "message": err_msg}

    # Use asyncio.to_thread for the synchronous requests.post call
    webhook_result = await asyncio.to_thread(send_webhook_request, endpoint=endpoint, action="list_tasks", input_data=conditions)


    if webhook_result["status"] == "initiated":
        req_id = webhook_result["req_id"]
        logger.debug(f"{inspect.currentframe().f_code.co_name}: Webhook initiated, waiting for results for req_id: {req_id}.")
        # await the async wait_for_results
        results = await retrieve_results_for_request(req_id)
        return results
    else:
        logger.error(f"{inspect.currentframe().f_code.co_name}: Webhook request failed: {webhook_result.get('message')}")
        return webhook_result


@mcp.tool()
async def get_remote_logons_for_endpoint(endpoint_hostname: str, time_start: str, time_stop: str) -> Dict[str, Any]:
    """
    Retrieve list of remote logons for a specific endpoint (hostname) by querying the Singularity Data Lake.
    This tool internally crafts and executes a PQL query.

    :param endpoint_hostname: The hostname/computer name to search for (mandatory)
    :param time_start: Start time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :param time_stop: Stop time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :return: List of dictionaries each mapping to a remote logon recorded on the specific endpoint


    """
    logger.info(
        f"MCP Tool: {inspect.currentframe().f_code.co_name} called with hostname: {endpoint_hostname}, time_start: {time_start}, time_stop: {time_stop}")

    try:
        # Craft the PQL query with format placeholders for you to populate
        pql_query = dedent("""\
        | left join remote_logons=(event.type = 'Login' and endpoint.name in:anycase('{endpoint_hostname}') and event.login.type in ('NETWORK_CLEAR_TEXT' ,'NETWORK_CREDENTIALS', 'NETWORK' ,'REMOTE_INTERACTIVE') and !(src.endpoint.ip.address in ('::1', '127.0.0.1'))  and src.endpoint.ip.address != null and !(event.login.userName contains '$')
        | columns login_time=strftime(event.time*1000000,'%Y-%m-%d %H:%M:%S'),src.endpoint.ip.address, dst_endpoint_hostname=endpoint.name, dst_endpoint_uuid=agent.uuid,   event.login.type,event.login.tgt.domainName, event.login.userName,successful_login=event.login.loginIsSuccessful, privileged_logon=event.login.isAdministratorEquivalent, failed_logon_reason=event.login.failureReason, timebucket_start=strftime(timebucket(event.time, '30m')*1000000,'%Y-%m-%d %H:%M:%S')),endpoint_info= ((event.type='IP Connect' and !(src.ip.address in ('127.0.0.1', '0.0.0.0','255.255.255.255')) and event.network.direction = 'OUTGOING') or (event.type = 'Login' and event.login.userName contains '$')
        | let src_hostname =  event.type == 'Login' ? upper(array_get(extract_matches(event.login.userName, '^(.*)\\\\$'),0)): upper(endpoint.name)
        | let username = event.type == 'IP Connect' ? src.process.user: ''
        | let src_ip_address = event.type == 'IP Connect' ? src.ip.address : src.endpoint.ip.address
        | group rfc1918_list=array_agg_distinct(src_ip_address), rfc1918_cnt=estimate_distinct(src_ip_address), tmp_endpoint_username_list=array_agg_distinct(username),tmp_username_cnt=estimate_distinct(username) by src_hostname,timestamp = timebucket(event.time, "30m")
        | let endpoint_username_list = array_filter(tmp_endpoint_username_list, func(x)->x!=''),username_cnt=len(endpoint_username_list)
        | columns src_hostname,timebucket_start=strftime(timestamp*1000000,'%Y-%m-%d %H:%M:%S'),rfc1918_zero=array_get(rfc1918_list,0), rfc1918_cnt,rfc1918_list) on remote_logons.src.endpoint.ip.address=rfc1918_zero, remote_logons.timebucket_start=endpoint_info.timebucket_start
        | columns timebucket_start,login_time,src.endpoint.ip.address,src_endpoint_hostname=src_hostname,dst_endpoint_hostname,event.login.type,account_domain=event.login.tgt.domainName,account_name=event.login.userName,successful_login,privileged_logon,failed_logon_reason,rfc1918_cnt,src_endpoint_rfc1918_list=rfc1918_list
        | sort +login_time
        """).format(
            endpoint_hostname=endpoint_hostname
        )

        # Prepare the query in the format expected by sdl_run_query
        queries = [
            {
                "start": time_start,
                "stop": time_stop,
                "query": pql_query
            }
        ]

        logger.debug(f"{inspect.currentframe().f_code.co_name}: Retrieving remote logons for hostname {endpoint_hostname}")

        # Call sdl_run_query internally
        results = await sdl_run_query(queries)

        # Add some metadata to indicate this came from get_ip_from_hostname
        if isinstance(results, dict) and results.get("status") == "success":
            results["source_tool"] = inspect.currentframe().f_code.co_name
            results["searched_hostname"] = endpoint_hostname
            results["time_range"] = f"{time_start} to {time_stop}"

        return results

    except Exception as e:
        error_msg = f"Error in {inspect.currentframe().f_code.co_name} for hostname {endpoint_hostname}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "status": "error",
            "message": error_msg,
            "hostname": endpoint_hostname,
            "time_start": time_start,
            "time_stop": time_stop
        }


@mcp.tool()
async def get_remote_logon_patterns_for_username(username: str, time_start: str, time_stop: str) -> Dict[str, Any]:
    """
    Generate a summary of logon patterns for a specific user (username) across all managed endpoints by querying the Singularity Data Lake.
    This is useful to get a high-level overview of how a user account was used/abused to log into one or multiple systems across an environment. The output will also include a breakdown of successful vs failed logons.
    This tool internally crafts and executes a PQL query.

    :param username: The username to search for (mandatory)
    :param time_start: Start time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :param time_stop: Stop time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :return: List of dictionaries each mapping to the set of logons performed by the specified user in a 30 minute timeframe


    """
    logger.info(
        f"MCP Tool: {inspect.currentframe().f_code.co_name} called with user: {username}, time_start: {time_start}, time_stop: {time_stop}")

    try:
        # Craft the PQL query with format placeholders for you to populate
        pql_query = dedent("""\
        | left join remote_logons=(event.type = 'Login' and event.login.userName in:anycase('{username}') and event.login.type in  ('NETWORK_CLEAR_TEXT' ,'NETWORK_CREDENTIALS', 'NETWORK', 'REMOTE_INTERACTIVE') and !(src.endpoint.ip.address in ('::1', '127.0.0.1'))  and src.endpoint.ip.address != null and !(event.login.userName contains '$')
        | columns event.time,src.endpoint.ip.address, endpoint.name, event.login.type,event.login.tgt.domainName, event.login.userName,event.login.loginIsSuccessful
        | group earliest_login_tmp=oldest(event.time),latest_login_tmp=newest(event.time),logon_types=array_agg_distinct(event.login.type), accessed_endpoint_cnt=estimate_distinct(endpoint.name), accessed_endpoints=array_agg_distinct(endpoint.name), successful_logon_cnt=count(event.login.loginIsSuccessful==true),failed_logon_cnt=count(event.login.loginIsSuccessful==false) by src.endpoint.ip.address, timestamp = timebucket(event.time, '30m'), event.login.userName,event.login.tgt.domainName
        | let delta_s=max(1,(latest_login_tmp - earliest_login_tmp)/1000)
        | let delta=strftime(delta_s*1000*1000000,'%H:%M:%S')
        | let earliest_login=strftime(earliest_login_tmp*1000000,'%Y-%m-%d %H:%M:%S'),latest_login=strftime(latest_login_tmp*1000000,'%Y-%m-%d %H:%M:%S')
        | columns event.login.tgt.domainName,event.login.userName,src.endpoint.ip.address, timebucket_start=strftime(timestamp*1000000,'%Y-%m-%d %H:%M:%S'),earliest_login,latest_login, delta_s,delta,successful_logon_cnt,failed_logon_cnt,accessed_endpoint_cnt,accessed_endpoints,logon_types),
        endpoint_info= ((event.type='IP Connect' and !(src.ip.address in ('127.0.0.1', '0.0.0.0','255.255.255.255')) and event.network.direction = 'OUTGOING') or (event.type = 'Login' and event.login.userName contains '$')
        | let src_hostname =  event.type == 'Login' ? array_get(extract_matches(event.login.userName, '^(.*)\\\\$'),0)): upper(endpoint.name)
        | let username = event.type == 'IP Connect' ? src.process.user: ''
        | let src_ip_address = event.type == 'IP Connect' ? src.ip.address : src.endpoint.ip.address
        | group rfc1918_list=array_agg_distinct(src_ip_address), rfc1918_cnt=estimate_distinct(src_ip_address), tmp_endpoint_username_list=array_agg_distinct(username),tmp_username_cnt=estimate_distinct(username) by src_hostname,timestamp = timebucket(event.time, "30m")
        | let endpoint_username_list = array_filter(tmp_endpoint_username_list, func(x)->x!=''),username_cnt=len(endpoint_username_list)
        | columns src_hostname,timebucket_start=strftime(timestamp*1000000,'%Y-%m-%d %H:%M:%S'),rfc1918_zero=array_get(rfc1918_list,0), rfc1918_cnt,rfc1918_list) on remote_logons.src.endpoint.ip.address=rfc1918_zero, remote_logons.timebucket_start=endpoint_info.timebucket_start
        | columns timebucket_start,earliest_login,latest_login,logon_types,account_domain=event.login.tgt.domainName, account_name=event.login.userName,src_endpoint_hostname=src_hostname,src.endpoint.ip.address, delta_s,delta,successful_logon_cnt,failed_logon_cnt,logon_target_endpoint_cnt=accessed_endpoint_cnt,logon_target_endpoints=accessed_endpoints,rfc1918_cnt,src_endpoint_rfc1918_list=rfc1918_list
        | sort +earliest_login
        """).format(
            username=username
        )

        # Prepare the query in the format expected by sdl_run_query
        queries = [
            {
                "start": time_start,
                "stop": time_stop,
                "query": pql_query
            }
        ]

        logger.debug(f"{inspect.currentframe().f_code.co_name}: Retrieving summary of remote logons for user {username}")

        # Call sdl_run_query internally
        results = await sdl_run_query(queries)

        # Add some metadata to indicate this came from get_ip_from_hostname
        if isinstance(results, dict) and results.get("status") == "success":
            results["source_tool"] = results["source_tool"] = inspect.currentframe().f_code.co_name
            results["searched_username"] = username
            results["time_range"] = f"{time_start} to {time_stop}"

        return results

    except Exception as e:
        error_msg = f"Error in {inspect.currentframe().f_code.co_name} for user {username}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "status": "error",
            "message": error_msg,
            "username": username,
            "time_start": time_start,
            "time_stop": time_stop
        }
@mcp.tool()
async def get_fuzzy_logon_session_windows(time_start: str, time_stop: str, username: str = None, endpoint_hostname: str = None,) -> Dict[str, Any]:
    """
    This tool retrieves a list of logon/logout event with limited correlation-metadata and attempts to rebuilt the logon sessions. You CANNOT provide an IPv4 address as the endpoint hostname
    Given either a username or an endpoint name or both, this method will analyse login/logouts and, using a loose estimate, attempt to pair login and logout events.
    Use this method if the analyst wants to:
        - automatically correlate login and logout events
    Do not use this method if the analysts wants to:
        - understand which rough observation window to use when investigating activity for a specific user on a system (use get_fuzzy_user_activity_windows instead)
        - obtain a list of distinct login/logout events


    If both username and hostname are provided, the method will analyse only the logon sessions for a given user on a given system.
    Providing only one of the two input values, the matching conditions are relaxed, and we will analyse either:
        Option 1. all logon sessions for a given users across all managed endpoints  OR
        Option 2. logons for all users on a specific endpoint (in the timeframe specified).
    This tool internally crafts and executes a PQL query.

    :param username: The username to search for (optional only if hostname is provided in input)
    :param endpoint_hostname: The endpoint name for which to analyse logon activity (optional only if username is provided)
    :param time_start: Start time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :param time_stop: Stop time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :return: list of dictionaries, each representing a fuzzy logon session window that includes the following information: login/logout timestamps, source IP, user, destination system, duration of session, privileged session (true/false)

    Example of results (in markdown)
    ### Fuzzy Logon Windows ###
    | login_time              | logout_time             | remote_logon   | login_types                            | source_IP       | dst_system       | user         | login_successful   | duration (s)   | duration (hh:mm:ss)   | privilege (Admin)   |
    |:------------------------|:------------------------|:---------------|:---------------------------------------|:----------------|:-----------------|:-------------|:-------------------|:---------------|:----------------------|:--------------------|
    | 2025-07-08 05:43:57.749 | 2025-07-08 05:57:15.488 | True           | NETWORK,REMOTE_INTERACTIVE,INTERACTIVE | 198.87.105.127  | DESKTOP-H281891  | jbob         | True               | 797.739        | 00:13:17              | True                |
    | 2025-07-08 05:57:14.227 | 2025-07-08 05:58:12.934 | True           | NETWORK,REMOTE_INTERACTIVE,INTERACTIVE | 198.87.105.127  | DESKTOP-H281891  | jbob         | True               | 58.707         | 00:00:58              | True                |
    | 2025-07-08 05:59:53.136 | 2025-07-08 06:01:12.418 | True           | NETWORK,REMOTE_INTERACTIVE,INTERACTIVE | 198.87.105.127  | DESKTOP-H281891  | jbob         | True               | 79.282         | 00:01:19              | True                |
    |                         | 2025-07-09 07:45:05.199 | False          |                                        |                 | DESKTOP-H281891  | jbob         |                    |                |                       |                     |
    | 2025-07-09 07:47:52.038 |                         | False          | INTERACTIVE                            | 127.0.0.1       | DESKTOP-H281891  | jbob         | False              |                |                       |                     |
    """

    THRESHOLD_MINUTES = 30

    logger.info(
        f"MCP Tool: {inspect.currentframe().f_code.co_name} called with user: {username or '[Any User]'}, hostname: {endpoint_hostname or '[Any Hostname]'} time_start: {time_start}, time_stop: {time_stop}")

    try:
        # Craft the PQL query with format placeholders for you to populate
        pql_query = dedent("""\
            event.category = 'logins' {hostname}  {username} AND !(event.login.userName contains '$') AND !(event.logout.tgt.user.name contains '$')
            | columns event.time, endpoint.name, event.type, src.endpoint.ip.address, event.login.isAdministratorEquivalent, event.login.loginIsSuccessful, event.login.type, event.login.userName, event.logout.tgt.user.name
            | sort +event.time
            """).format(
            username=f"AND (event.login.userName in:anycase('{username}') or event.logout.tgt.user.name in:anycase('{username}')) " if username else "",
            hostname=f"AND endpoint.name in:anycase('{endpoint_hostname}')" if endpoint_hostname else ""
        )

        # Prepare the query in the format expected by sdl_run_query
        queries = [
            {
                "start": time_start,
                "stop": time_stop,
                "query": pql_query
            }
        ]

        logger.debug(
            f"{inspect.currentframe().f_code.co_name}: Retrieving fuzzy logon windows for combination {username or '[Empty User]'}/{endpoint_hostname or '[Empty Hostname]'}")

        # Call sdl_run_query internally
        results = await sdl_run_query(queries)

        # Add some metadata to indicate this came from get_ip_from_hostname
        if isinstance(results, dict) and results.get("status") == "success":
            results["source_tool"] = results["source_tool"] = inspect.currentframe().f_code.co_name
            results["searched_username"] = username
            results["time_range"] = f"{time_start} to {time_stop}"

            correlated_events = correlate_login_logout(results["data"][0]["output"])
            collapsed_logons = collapse_orphans(correlated_events, threshold_minutes=THRESHOLD_MINUTES)
            #rewriting rows
            results["data"][0]["output"]["pql_rows"] = collapsed_logons



        return results

    except Exception as e:
        error_msg = f"Error in {inspect.currentframe().f_code.co_name} for combination {username or '[Empty User]'}/{endpoint_hostname or '[Empty Hostname]'}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "status": "error",
            "message": error_msg,
            "username": username,
            "time_start": time_start,
            "time_stop": time_stop
        }

@mcp.tool()
async def get_fuzzy_user_activity_windows(time_start: str, time_stop: str, username: str = None, endpoint_hostname: str = None,) -> Dict[str, Any]:
    """
    This tools provides a high-level answer to the question: "Which user was active on which system, from where, and for approximately for how long?
    This method should be used whenever the analysts wants to triage a system and needs a loose estimate on the observation window (time_start, time_stop) to be used for investigative purposes (triage and timelining activities)

    Use this method if the analyst wants to:
        - understand which observation window to use when investigating activity for a specific user on a system (use get_fuzzy_user_activity_windows instead)
        Do not use this method if the analysts wants to:
        -  attempt to correlate login and logout events without further processing (use get_fuzzy_logon_session_windows instead)
        - obtain a list of distinct login/logout events

    If both username and hostname are provided, the method will analyse only the logon sessions for a given user on a given system.
    Providing only one of the two input values, the matching conditions are relaxed, and we will analyse either:
        Option 1. all logon sessions for a given users across all managed endpoints  OR
        Option 2. logons for all users on a specific endpoint (in the timeframe specified).
    This tool internally crafts and executes a PQL query.

    :param username: The username (domain user) to search for (optional only if hostname is provided in input). Do not provide the domain name (account domain) in input, only the username (E.g 'Bob')
    :param endpoint_hostname: The endpoint name for which to analyse logon activity (optional only if username is provided)
    :param time_start: Start time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :param time_stop: Stop time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :return: list of dictionaries, each representing a  collapsed observation window to be used for further analysis when an analyst want a rough estimate on how long a user/attacker was active on an endpoint.

    Example of final tbale (in markdown) returned by this method
    ### Fuzzy User Activity Timeframe Summary ###
    | Date       | User         | source_IP       | dst_system       | Earliest Activity (-10 min)   | Latest Activity (+10 min)   |   Duration (s) | Duration (hh:mm:ss)   | Activity Types           |
    |:-----------|:-------------|:----------------|:-----------------|:------------------------------|:----------------------------|---------------:|:----------------------|:-------------------------|
    | 2025-07-08 | jbob         | 100.124.105.127 | DESKTOP-H281891  | 2025-07-08 05:33:57           | 2025-07-08 06:11:12         |           1035 | 00:17:14              | NETWORK, RDP/Interactive |
    """

    CONSOLIDATION_THRESHOLD_HOURS = 3
    BUFFER_MINUTES = 0


    logger.info(
        f"MCP Tool: {inspect.currentframe().f_code.co_name} called with user: {username or '[Any User]'}, hostname: {endpoint_hostname or '[Any Hostname]'} time_start: {time_start}, time_stop: {time_stop}")

    try:
        # Craft the PQL query with format placeholders for you to populate
        pql_query = dedent("""\
        event.category = 'logins' {hostname}  {username} AND !(event.login.userName contains '$') AND !(event.logout.tgt.user.name contains '$')
        | columns event.time, endpoint.name, event.type, src.endpoint.ip.address, event.login.isAdministratorEquivalent, event.login.loginIsSuccessful, event.login.type, event.login.userName, event.logout.tgt.user.name
        | sort +event.time
        """).format(
            username=f"AND (event.login.userName in:anycase('{username}') or event.logout.tgt.user.name in:anycase('{username}')) " if username else "",
            hostname=f"AND endpoint.name in:anycase('{endpoint_hostname}')" if endpoint_hostname else ""
        )

        # Prepare the query in the format expected by sdl_run_query
        queries = [
            {
                "start": time_start,
                "stop": time_stop,
                "query": pql_query
            }
        ]

        logger.debug(f"{inspect.currentframe().f_code.co_name}: Retrieving fuzzy logon windows for combination {username or '[Empty User]'}/{endpoint_hostname or '[Empty Hostname]'}")

        # Call sdl_run_query internally
        results = await sdl_run_query(queries)

        # Add some metadata to indicate this came from get_ip_from_hostname
        if isinstance(results, dict) and results.get("status") == "success":
            results["source_tool"] = results["source_tool"] = inspect.currentframe().f_code.co_name
            results["searched_username"] = username
            results["time_range"] = f"{time_start} to {time_stop}"


            correlated_events = correlate_login_logout(results["data"][0]["output"])
            collapsed_logons = collapse_orphans(correlated_events, threshold_minutes=30)
            activity_summary_rows = generate_activity_summary(collapsed_logons,consolidation_threshold_hours=CONSOLIDATION_THRESHOLD_HOURS,buffer_minutes=BUFFER_MINUTES, group_by_source_ip=True)
            # rewriting rows
            results["data"][0]["output"]["pql_rows"] = activity_summary_rows

        return results

    except Exception as e:
        error_msg = f"Error in {inspect.currentframe().f_code.co_name} for combination {username or '[Empty User]'}/{endpoint_hostname or '[Empty Hostname]'}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "status": "error",
            "message": error_msg,
            "username": username,
            "time_start": time_start,
            "time_stop": time_stop
        }


@mcp.tool()
async def get_detailed_logons_for_username(username: str, time_start: str, time_stop: str) -> Dict[str, Any]:
    """
    Retrieve the full list of local and remote logons for a specific user (username) across all managed endpoints by querying the Singularity Data Lake.
    This tool internally crafts and executes a PQL query.

    :param username: The username to search for (mandatory)
    :param time_start: Start time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :param time_stop: Stop time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :return: List of dictionaries each mapping a  logon performed by the specified user


    """
    logger.info(
        f"MCP Tool: {inspect.currentframe().f_code.co_name} called with user: {username}, time_start: {time_start}, time_stop: {time_stop}")

    try:
        # Craft the PQL query with format placeholders for you to populate
        pql_query = dedent("""\
        | left join remote_logons=(event.type = 'Login' and event.login.userName in:anycase('{username}') and event.login.type in ('NETWORK_CLEAR_TEXT' ,'NETWORK_CREDENTIALS', 'NETWORK', 'REMOTE_INTERACTIVE','CACHED_REMOTE_INTERACTIVE' ,'CACHED_INTERACTIVE' ,'INTERACTIVE' ,'UNLOCK', 'CACHED_UNLOCK')  and src.endpoint.ip.address != null and !(event.login.userName contains '$')
        | columns login_time=strftime(event.time*1000000,'%Y-%m-%d %H:%M:%S'),src.endpoint.ip.address, dst_endpoint_hostname=endpoint.name, dst_endpoint_uuid=agent.uuid,   event.login.type,event.login.tgt.domainName, event.login.userName,successful_login=event.login.loginIsSuccessful, privileged_logon=event.login.isAdministratorEquivalent, failed_logon_reason=event.login.failureReason, timebucket_start=strftime(timebucket(event.time, '30m')*1000000,'%Y-%m-%d %H:%M:%S')),
        endpoint_info= ((event.type='IP Connect' and !(src.ip.address in ('127.0.0.1', '0.0.0.0','255.255.255.255')) and event.network.direction = 'OUTGOING') or (event.type = 'Login' and event.login.userName contains '$')
        | let src_hostname =  event.type == 'Login' ? upper(array_get(extract_matches(event.login.userName, '^(.*)\\\\$'),0)): upper(endpoint.name)
        | let username = event.type == 'IP Connect' ? src.process.user: ''
        | let src_ip_address = event.type == 'IP Connect' ? src.ip.address : src.endpoint.ip.address
        | group rfc1918_list=array_agg_distinct(src_ip_address), rfc1918_cnt=estimate_distinct(src_ip_address), tmp_endpoint_username_list=array_agg_distinct(username),tmp_username_cnt=estimate_distinct(username) by src_hostname,timestamp = timebucket(event.time, "30m")
        | let endpoint_username_list = array_filter(tmp_endpoint_username_list, func(x)->x!=''),username_cnt=len(endpoint_username_list)
        | columns src_hostname,timebucket_start=strftime(timestamp*1000000,'%Y-%m-%d %H:%M:%S'),rfc1918_zero=array_get(rfc1918_list,0), rfc1918_cnt,rfc1918_list) on remote_logons.src.endpoint.ip.address=rfc1918_zero, remote_logons.timebucket_start=endpoint_info.timebucket_start
        | columns timebucket_start,login_time,src.endpoint.ip.address, src_endpoint_hostname=src_hostname,dst_endpoint_hostname,event.login.type,account_domain=event.login.tgt.domainName,account_name=event.login.userName,successful_login,privileged_logon,failed_logon_reason,rfc1918_cnt,src_endpoint_rfc1918_list=rfc1918_list
        | sort +login_time
        """).format(
            username=username
        )

        # Prepare the query in the format expected by sdl_run_query
        queries = [
            {
                "start": time_start,
                "stop": time_stop,
                "query": pql_query
            }
        ]

        logger.debug(f"{inspect.currentframe().f_code.co_name}: Retrieving full list of logons for user {username}")

        # Call sdl_run_query internally
        results = await sdl_run_query(queries)

        # Add some metadata to indicate this came from get_ip_from_hostname
        if isinstance(results, dict) and results.get("status") == "success":
            results["source_tool"] = results["source_tool"] = inspect.currentframe().f_code.co_name
            results["searched_username"] = username
            results["time_range"] = f"{time_start} to {time_stop}"

        return results

    except Exception as e:
        error_msg = f"Error in {inspect.currentframe().f_code.co_name} for user {username}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "status": "error",
            "message": error_msg,
            "username": username,
            "time_start": time_start,
            "time_stop": time_stop
        }


@mcp.tool()
async def find_endpoint_hostname_from_ip(ip_address: str, time_start: str, time_stop: str) -> Dict[str, Any]:
    """
    Attempt to find the hostname for a managed endpoint that at a given point in time had the lease for the IP address provided in input.
    This method should only be used for historical resolutions (IP -> Hostname). To obtain the current IP to Hostname mapping, a dedicated tool listing current assests/endpoints should be used instead for better accuracy.
    When invoking this tool, you should pair the invokation of any other tool (if it exists) to list the current list of asset/endpoint that have that specific IP address.
    The information from the multiple tool invokation could then be correlated/merged.
    This tool internally crafts and executes a PQL query that identifies outbound connections from all managed endpoints during the observation timeframe and extracts the source IP for the connections. If there's a historical match for the input IP, the information about the endpoint is returned.

    :param ip_address: The IP to search for (mandatory)
    :param time_start: Start time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :param time_stop: Stop time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :return: List of dictionaries each mapping a  logon performed by the specified user
    """
    logger.info(
        f"MCP Tool: {inspect.currentframe().f_code.co_name} called with IP: {ip_address}, time_start: {time_start}, time_stop: {time_stop}")

    try:
        # Craft the PQL query with format placeholders for you to populate
        pql_query = dedent("""\
        (event.type='IP Connect' and src.ip.address in ('{ip_address}') and event.network.direction = 'OUTGOING') or (event.type = 'Login' and src.endpoint.ip.address in ('{ip_address}') and event.login.userName contains '$')
        | let src_hostname =  event.type == 'Login' ? array_get(extract_matches(event.login.userName, '^(.*)\\\\$'),0): upper(endpoint.name)
        | let username = event.type == 'IP Connect' ? src.process.user: ''
        | let src_ip_address = event.type == 'IP Connect' ? src.ip.address : src.endpoint.ip.address
        | columns event.time, event.type, endpoint.name, src_ip_address, event.login.userName, src_hostname, username
        | group rfc1918_list=array_agg_distinct(src_ip_address), rfc1918_cnt=estimate_distinct(src_ip_address), tmp_endpoint_username_list=array_agg_distinct(username),tmp_username_cnt=estimate_distinct(username) by src_hostname,timestamp = timebucket(event.time, "12h")
        | let endpoint_username_list = array_filter(tmp_endpoint_username_list, func(x)->x!=''),username_cnt=len(endpoint_username_list)
        | columns timebucket_start=strftime(timestamp*1000000,"%Y-%m-%d %H:%M:%S"),src_hostname,mapped_ipv4=array_get(rfc1918_list,0),username_cnt,endpoint_username_list, rfc1918_cnt,rfc1918_list
        | sort timebucket_start
        """).format(
            ip_address=ip_address
        )

        # Prepare the query in the format expected by sdl_run_query
        queries = [
            {
                "start": time_start,
                "stop": time_stop,
                "query": pql_query
            }
        ]

        logger.debug(f"{inspect.currentframe().f_code.co_name}: Finding hostname for IP {ip_address} for timeframe [{time_start},{time_stop}]")

        # Call sdl_run_query internally
        results = await sdl_run_query(queries)

        # Add some metadata to indicate this came from get_ip_from_hostname
        if isinstance(results, dict) and results.get("status") == "success":
            results["source_tool"] = results["source_tool"] = inspect.currentframe().f_code.co_name
            results["searched_ip_address"] = ip_address
            results["time_range"] = f"{time_start} to {time_stop}"

        return results

    except Exception as e:
        error_msg = f"Error in {inspect.currentframe().f_code.co_name} for IP {ip_address}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "status": "error",
            "message": error_msg,
            "ip_address": ip_address,
            "time_start": time_start,
            "time_stop": time_stop
        }


@mcp.tool()
async def get_top_users_for_endpoints(endpoint_list: List[str], time_start: str, time_stop: str) -> Dict[str, Any]:
    """
    Retrieve a list of most active for every hostname provided in input to establish the most likely top user/system owner.
    This tool internally crafts and executes a PQL query that focuses on the frequency of Login and Process Creation events.
    When the user does not explictly specify a timeframe (start, stop), consider the default observation window: [last_10_days, now]

    :param endpoint_list: The list of hostname/computer name to search for (mandatory)
    :param time_start: Start time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :param time_stop: Stop time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :return: List of rows representing the frequency of occurence of Process Create/Logon events for users on the specified endpoints.


    """
    logger.info(
        f"MCP Tool: {inspect.currentframe().f_code.co_name} called with hostname(s): {endpoint_list}, time_start: {time_start}, time_stop: {time_stop}")

    try:
        # Craft the PQL query with format placeholders for you to populate
        pql_query = dedent("""\
        | union (event.type = 'Login' and endpoint.name in ({fmt_endpoint_list}) and event.login.type in ('CACHED_INTERACTIVE', 'CACHED_REMOTE_INTERACTIVE' ,'CACHED_UNLOCK' ,'NETWORK' ,'NETWORK_CLEAR_TEXT' ,'NETWORK_CREDENTIALS' ,'REMOTE_INTERACTIVE' ,'UNLOCK' ) 
        | group logon_cnt=count() by event.login.userName, endpoint.name | columns endpoint.name, username=event.login.userName , event_cnt=logon_cnt, event_type='Login'), (event.type = 'Process Creation' and endpoint.name in ({fmt_endpoint_list}) and !(src.process.user in ({excluded_usernames})) 
        | group process_creation_count=count() by src.process.user, endpoint.name | columns endpoint.name, username=src.process.user, event_cnt=process_creation_count, event_type='Process Creation')
        | filter !(username contains '$')
        | sort endpoint.name, -event_cnt
        """).format(
            fmt_endpoint_list=",".join(["'{}'".format(hostname) for hostname in endpoint_list]),
            excluded_usernames= ",".join(["'{}'".format(hostname) for hostname in ['NT AUTHORITY\\\\LOCAL SERVICE', 'NT AUTHORITY\\\\NETWORK SERVICE', 'NT AUTHORITY\\\\SYSTEM' , 'SYSTEM']])
        )

        # Prepare the query in the format expected by sdl_run_query
        queries = [
            {
                "start": time_start,
                "stop": time_stop,
                "query": pql_query
            }
        ]

        logger.debug(f"{inspect.currentframe().f_code.co_name}: Retrieving remote logons for hostname(s) {endpoint_list}")

        # Call sdl_run_query internally
        results = await sdl_run_query(queries)

        # Add some metadata to indicate this came from get_ip_from_hostname
        if isinstance(results, dict) and results.get("status") == "success":
            results["source_tool"] = inspect.currentframe().f_code.co_name
            results["searched_endpoints"] = endpoint_list
            results["time_range"] = f"{time_start} to {time_stop}"

        return results

    except Exception as e:
        error_msg = f"Error in {inspect.currentframe().f_code.co_name} for hostname(s) {endpoint_list}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "status": "error",
            "message": error_msg,
            "endpoint_list": endpoint_list,
            "time_start": time_start,
            "time_stop": time_stop
        }


@mcp.tool()
async def get_detailed_process_list(time_start: str, time_stop: str, username: str = None, endpoint_hostname: str = None) -> Dict[str, Any]:
    """
    This tool retrieves a detailed list of process creation events for a specific user and/or endpoint within a given timeframe.
    Given either a username or an endpoint name or both, this method will retrieve all process creation events matching the criteria.
    

    If both username and hostname are provided, the method will retrieve only the process creation events for the given user on the given system.
    Providing only one of the two input values, the matching conditions are relaxed, and we will retrieve either:
        Option 1. all process creation events for a given user across all managed endpoints  OR
        Option 2. all process creation events for all users on a specific endpoint (in the timeframe specified).
    This tool internally crafts and executes a PQL query.

    :param username: The username to search for (optional only if hostname is provided in input)
    :param endpoint_hostname: The endpoint name for which to analyze process creation activity (optional only if username is provided)
    :param time_start: Start time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :param time_stop: Stop time for the search in format "YYYY-MM-DD HH:MM:SS" (mandatory)
    :return: List of dictionaries, each representing a process creation event that includes detailed information such as: process path, command line, parent process, process IDs, SHA1 hashes, signature status, etc.
    """

    logger.info(
        f"MCP Tool: {inspect.currentframe().f_code.co_name} called with user: {username or '[Any User]'}, hostname: {endpoint_hostname or '[Any Hostname]'} time_start: {time_start}, time_stop: {time_stop}")


    try:
        # Craft the PQL query with format placeholders for dynamic population
        pql_query = dedent("""\
            event.type = 'Process Creation' {username} {hostname}
            | columns event.time, endpoint.name, src.process.parent.user, src.process.parent.image.path, src.process.parent.name, src.process.parent.cmdline, src.process.user, src.process.image.path, src.process.cmdline, tgt.process.user, tgt.process.image.path, tgt.process.cmdline, src.process.parent.storyline.id, src.process.storyline.id, tgt.process.storyline.id, src.process.parent.image.sha1, src.process.image.sha1, tgt.process.image.sha1, src.process.parent.signedStatus, src.process.signedStatus, src.process.verifiedStatus, tgt.process.signedStatus, tgt.process.verifiedStatus, src.process.parent.pid, src.process.pid, tgt.process.pid
            | sort +event.time
            | limit 10000
            """).format(
            username=f"AND (src.process.parent.user contains '{username}' or src.process.user contains '{username}' or tgt.process.user contains '{username}')" if username else "",
            hostname=f"AND endpoint.name in:anycase('{endpoint_hostname}')" if endpoint_hostname else ""
        )

        # Prepare the query in the format expected by sdl_run_query
        queries = [
            {
                "start": time_start,
                "stop": time_stop,
                "query": pql_query
            }
        ]

        logger.debug(
            f"{inspect.currentframe().f_code.co_name}: Retrieving detailed process list for combination {username or '[Empty User]'}/{endpoint_hostname or '[Empty Hostname]'}")

        # Call sdl_run_query internally
        results = await sdl_run_query(queries)

        # Add metadata to the results
        if isinstance(results, dict) and results.get("status") == "success":
            results["source_tool"] = inspect.currentframe().f_code.co_name
            results["searched_username"] = username
            results["searched_hostname"] = endpoint_hostname
            results["time_range"] = f"{time_start} to {time_stop}"

        return results

    except Exception as e:
        error_msg = f"Error in {inspect.currentframe().f_code.co_name} for combination {username or '[Empty User]'}/{endpoint_hostname or '[Empty Hostname]'}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "status": "error",
            "message": error_msg,
            "username": username,
            "endpoint_hostname": endpoint_hostname,
            "time_start": time_start,
            "time_stop": time_stop
        }



# --- Main execution block ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP Server for Claude")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="sse",
                        help="Transport method to use (default: sse)")
    parser.add_argument("--host", default="127.0.0.1", help="Host for SSE server (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port for SSE server (default: 8000)")
    args = parser.parse_args()

    logger.info(f"Starting MCP server with {args.transport} transport on {args.host}:{args.port}...")
    logger.info(f"Logs also being written to {LOG_FILE_PATH}")

    if args.transport == "sse":
        try:
            import uvicorn
        except ImportError:
            logger.error("Please install 'uvicorn' for SSE support ('pip install uvicorn').")
            sys.exit(1)

        # Get the ASGI app directly from the FastMCP instance using sse_app()
        app = mcp.sse_app()

        # Uvicorn handles its own logging by default. You can configure it
        # via uvicorn.run arguments if needed, but our logger 'mcp-server'
        # should still receive messages from our code.
        uvicorn.run(app, host=args.host, port=args.port, log_config=None) # Disable uvicorn's default logging config to avoid conflicts if necessary

    else: # stdio transport
        logger.info("Running stdio transport")
        # For stdio, logs will go to the handlers we configured (file and stderr)
        # stdio transport is synchronous from the perspective of mcp.run()
        mcp.run(transport="stdio")
