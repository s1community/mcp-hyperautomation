# utils/db_manager.py

import os
import logging
import asyncio
from typing import Any, Optional, Dict, List

from .google_big_query_client import GoogleBigQueryClient as BigQueryClient


logger = logging.getLogger(__name__)


class DB_Manager:
    SUPPORTED_SERVICES = ["gsheet", "bigquery"]

    def __init__(self,
                 service_type: str,
                 credentials_path: str,  # This is the primary config from mcp_server
                 default_max_retries: int = 300,
                 default_retry_delay: int = 1
                 # No service_client_config_overrides needed from mcp_server.
                 # Client will use its own env var lookups / defaults.
                 ):

        self.service_type = service_type.lower()
        self._client: Any = None
        self.default_max_retries = default_max_retries
        self.default_retry_delay = default_retry_delay

        if self.service_type not in self.SUPPORTED_SERVICES:
            raise ValueError(f"Unsupported DB service type: {self.service_type}. Supported: {self.SUPPORTED_SERVICES}")

        logger.info(
            f"DB_Manager: Initializing for service '{self.service_type}' with credentials path hint: '{credentials_path}'")

        try:
            if self.service_type == "gsheet":
                # GSheetClient now handles its own config (spreadsheet_id, sheet_name, etc.)
                # from environment variables or its internal defaults.
                # DB_Manager only needs to pass the common credentials_path.
                self._client = GSheetClient(
                    credentials_path=credentials_path
                )
                logger.info("GSheetClient initialized by DB_Manager.")

            elif self.service_type == "bigquery":
                # BQClientImpl would similarly handle its own project_id, dataset_id from env or defaults
                self._client = BigQueryClient(
                    credentials_path=credentials_path
                )
                logger.info("BigQueryClient initialized by DB_Manager.")
            else:
                raise NotImplementedError(f"DB_Manager initialization for {self.service_type} not implemented.")

        except FileNotFoundError as fnf:
            logger.error(f"DB_Manager: Credentials file error during client init for '{self.service_type}' - {fnf}",
                         exc_info=False)
            raise
        except ValueError as ve:  # Catches config errors from client init (e.g. missing GOOGLE_SHEET_ID if no fallback)
            logger.error(f"DB_Manager: Configuration value error during client init for '{self.service_type}' - {ve}",
                         exc_info=False)
            raise
        except Exception as e:
            logger.error(f"DB_Manager: Failed to initialize client for {self.service_type}: {e}", exc_info=True)
            raise

    async def retrieve_results_from_db(self,
                                       req_id: str,
                                       expected_row_number: int = 1,
                                       max_retries_override: Optional[int] = None,
                                       retry_delay_override: Optional[int] = None,
                                       **client_specific_fetch_kwargs: Any
                                       # For overrides passed to client's fetch method
                                       ) -> Dict[str, Any]:
        # ... (This method's internal polling logic remains the same, calling self._client.fetch_results_by_req_id)
        if not self._client or not hasattr(self._client, 'fetch_results_by_req_id'):
            msg = f"DB client for '{self.service_type}' unavailable or missing 'fetch_results_by_req_id' method."
            logger.error(msg)
            return {"status": "error", "req_id": req_id, "message": msg}

        current_max_retries = max_retries_override or self.default_max_retries
        current_retry_delay = retry_delay_override or self.default_retry_delay

        logger.debug(
            f"DB_Manager: Polling for req_id='{req_id}', expecting {expected_row_number}. Max Retries: {current_max_retries}, Delay: {current_retry_delay}s.")
        fetched_data: List[Any] = []

        for attempt in range(current_max_retries):
            logger.debug(f"DB_Manager: Attempt {attempt + 1}/{current_max_retries} for req_id '{req_id}'.")
            try:
                current_rows = await self._client.fetch_results_by_req_id(req_id, **client_specific_fetch_kwargs)
                if current_rows is not None:
                    logger.debug(f"DB_Manager: Client returned {len(current_rows)} row(s) for req_id '{req_id}'.")
                    fetched_data = current_rows
                    if len(fetched_data) >= expected_row_number:
                        logger.info(
                            f"DB_Manager: Sufficient results ({len(fetched_data)}) found for req_id '{req_id}'.")
                        return {"status": "success", "req_id": req_id, "data": fetched_data}
                    else:
                        logger.debug(
                            f"DB_Manager: Found {len(fetched_data)}, expecting {expected_row_number}. Continuing poll.")
                else:
                    logger.debug(f"DB_Manager: Client returned None for req_id '{req_id}' this poll.")
            except Exception as e:
                logger.error(f"DB_Manager: Unhandled error during client fetch for req_id '{req_id}': {e}",
                             exc_info=True)
                return {"status": "error", "req_id": req_id, "message": f"DB client fetch error: {str(e)}"}

            if attempt < current_max_retries - 1:
                logger.debug(f"DB_Manager: Sleeping {current_retry_delay}s for req_id '{req_id}'.")
                await asyncio.sleep(current_retry_delay)

        logger.warning(f"DB_Manager: Polling timed out for req_id '{req_id}' after {current_max_retries} retries.")
        if fetched_data:
            return {"status": "timeout_partial", "req_id": req_id,
                    "message": f"Timed out. Found {len(fetched_data)}/{expected_row_number} expected rows.",
                    "data": fetched_data}
        return {"status": "timeout_empty", "req_id": req_id, "message": "Timed out. No rows found."}