import os
import json
import logging
import asyncio
from typing import Optional, List, Dict, Any

from google.cloud import bigquery
from google.oauth2.service_account import Credentials
from google.auth.exceptions import RefreshError
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class GoogleBigQueryClient:
    # Define scopes if needed for credentials, though BigQuery client often handles this.
    # SCOPES = ['https://www.googleapis.com/auth/bigquery', 'https://www.googleapis.com/auth/cloud-platform']

    def __init__(self, credentials_path: str):
        self.project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
        self.dataset_id = os.getenv("BIGQUERY_DATASET_ID")
        self.table_id = os.getenv("BIGQUERY_TABLE_ID")
        self.req_id_column = os.getenv("BIGQUERY_REQ_ID_COLUMN", "req_id")  # Default to 'req_id'


        self.columns_to_select_list = ["output"]
        self.columns_to_select_str = ", ".join(self.columns_to_select_list)

        if not all([self.project_id, self.dataset_id, self.table_id, self.columns_to_select_str]):
            missing_configs = []
            if not self.project_id: missing_configs.append("GOOGLE_CLOUD_PROJECT")
            if not self.dataset_id: missing_configs.append("BIGQUERY_DATASET_ID")
            if not self.table_id: missing_configs.append("BIGQUERY_TABLE_ID")
            if not self.columns_to_select_str: missing_configs.append("BIGQUERY_COLUMNS_TO_SELECT (or it was empty)")
            raise ValueError(
                f"GoogleBigQueryClient: Missing one or more required environment variables: {', '.join(missing_configs)}")

        self.credentials_path = credentials_path
        self.credentials: Optional[Credentials] = self._load_credentials(self.credentials_path)
        self.client: Optional[bigquery.Client] = self._initialize_client()

        self.fully_qualified_table_id = f"{self.project_id}.{self.dataset_id}.{self.table_id}"

        logger.info(
            f"GoogleBigQueryClient initialized. Project: '{self.project_id}', "
            f"Dataset: '{self.dataset_id}', Table: '{self.table_id}', "
            f"ReqID Col: '{self.req_id_column}', Selecting: '{self.columns_to_select_str}'"
        )

    def _resolve_credentials_path(self, path: str) -> str:
        """Resolves the credentials file path, checking absolute and relative paths."""
        if os.path.isabs(path) and os.path.exists(path):
            return path

        # Try relative to current working directory (less common for utils, but for completeness)
        # if os.path.exists(path):
        # return os.path.abspath(path)

        if not os.path.isabs(path):
            # Try relative to this file's directory (utils/)
            module_dir = os.path.dirname(os.path.abspath(__file__))
            resolved_path_module = os.path.join(module_dir, path)
            if os.path.exists(resolved_path_module):
                return resolved_path_module

            # Try relative to the project directory (one level up from utils/)
            project_dir = os.path.dirname(module_dir)
            resolved_path_project = os.path.join(project_dir, path)
            if os.path.exists(resolved_path_project):
                return resolved_path_project

        logger.error(f"Credentials file not found at '{path}' or via resolved relative paths.")
        raise FileNotFoundError(f"Credentials file not found at '{path}' or via resolved relative paths.")

    def _load_credentials(self, credentials_path: str) -> Optional[Credentials]:
        try:
            resolved_path = self._resolve_credentials_path(credentials_path)
            # You might need to specify scopes if the client library doesn't infer them sufficiently
            # creds = Credentials.from_service_account_file(resolved_path, scopes=self.SCOPES)
            creds = Credentials.from_service_account_file(resolved_path)
            logger.info(f"Service account credentials loaded successfully from: {resolved_path}")
            return creds
        except FileNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Error loading service account credentials from {credentials_path}: {e}", exc_info=True)
            return None

    def _initialize_client(self) -> Optional[bigquery.Client]:
        if not self.credentials:
            logger.error("Credentials not loaded, cannot initialize BigQuery client.")
            return None
        try:
            client = bigquery.Client(credentials=self.credentials, project=self.project_id)
            logger.info(f"BigQuery client initialized for project: {client.project}")
            return client
        except Exception as e:
            logger.error(f"Failed to initialize BigQuery client: {e}", exc_info=True)
            return None


    def _fetch_data_sync(self, sql_query: str, job_config: bigquery.QueryJobConfig) -> List[Dict[str, Any]]:
        """
        Synchronously executes the BigQuery query and fetches results.
        This is intended to be run in a separate thread via asyncio.to_thread.
        """
        if not self.client:  # Should ideally not be hit if called after client init check
            logger.error("BigQuery client not initialized. Cannot execute query.")
            return []

        try:
            query_job = self.client.query(sql_query, job_config=job_config)
            # Wait for the job to complete and get results
            rows_iterator = query_job.result()  # This is a blocking call

            # Convert rows to a list of dictionaries
            # Each item in rows_iterator is a bigquery.Row object, which acts like a tuple/dict
            results = [dict(row) for row in rows_iterator]
            return results
        except RefreshError as re:
            # Log here or let the caller handle it, for consistency let's log specific auth errors
            logger.error(
                f"Google Auth RefreshError during BigQuery query execution: {re}. Check credentials and permissions.",
                exc_info=True
            )
            raise  # Re-raise to be caught by the async wrapper's general exception handler
        except Exception as e:
            logger.error(f"An unexpected error occurred during synchronous BigQuery query execution: {e}",
                         exc_info=True)
            raise  # Re-raise to be caught by the async wrapper's general exception handler

    async def fetch_results_by_req_id(self, req_id_value: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Fetches rows from the BigQuery table that match the given req_id.
        Uses asyncio.to_thread to run the blocking query operation.

        Args:
            req_id_value: The request ID to filter by.
            **kwargs: Potentially for future use or specific overrides, currently ignored.

        Returns:
            A list of dictionaries, where each dictionary represents a row.
            Returns an empty list if no rows are found or in case of an error.
        """
        if not self.client:
            logger.error("BigQuery client not initialized. Cannot fetch results.")
            return []

        if not req_id_value:
            logger.warning("req_id_value is empty or None. Cannot fetch results.")
            return []

        sql_query = f"""
            SELECT {self.columns_to_select_str}
            FROM `{self.fully_qualified_table_id}`
            WHERE {self.req_id_column} = @req_id_param
        """
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("req_id_param", "STRING", req_id_value)
            ]
        )

        logger.debug(f"Preparing to execute BigQuery query for req_id '{req_id_value}'.")

        try:
            # Run the synchronous function in a separate thread
            results = await asyncio.to_thread(
                self._fetch_data_sync,  # Call the new synchronous method
                sql_query,
                job_config
            )

            if results:
                logger.info(f"Found {len(results)} row(s) for req_id '{req_id_value}'.")
            else:
                pass
            return results

        except Exception as e:  # Catches errors re-raised from _fetch_data_sync or other issues
            # More specific error logging was done in _fetch_data_sync for auth errors
            # This catches broader errors during the to_thread call or if _fetch_data_sync
            # raises something unexpected before specific logging.
            logger.error(f"An error occurred in fetch_results_by_req_id for req_id '{req_id_value}': {e}",
                         exc_info=True)
            return []

# (This code goes at the end of utils/big_query_client.py, outside the class definition)

if __name__ == "__main__":
    import argparse
    import os  # Already imported, but good to ensure context
    from dotenv import load_dotenv

    # Load environment variables from .env file if it exists
    # Assumes .env is in the project root, adjust path if necessary
    # For example, if utils is in project_root/utils, then:
    # load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))
    load_dotenv()

    parser = argparse.ArgumentParser(description="Test BigQuery client: fetch rows by req_id.")
    parser.add_argument("req_id", type=str, help="The request ID to search for.")
    parser.add_argument(
        "--creds",
        type=str,
        default=os.getenv("CREDENTIALS_FILE_PATH"),  # Get from env var by default
        help="Path to the service account credentials JSON file. "
             "Defaults to CREDENTIALS_FILE_PATH environment variable."
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level for the test script."
    )

    args = parser.parse_args()

    # Basic logging setup for the test script
    logging.basicConfig(level=getattr(logging, args.log_level.upper()),
                        format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

    # Re-set logger level for this specific client if needed,
    # though basicConfig might cover it if logger name is part of root.
    # logging.getLogger(__name__).setLevel(getattr(logging, args.log_level.upper()))

    if not args.creds:
        logger.error("Credentials file path not provided. Set CREDENTIALS_FILE_PATH env var or use --creds argument.")
        exit(1)


    async def main_test(req_id_to_test: str, credentials_file: str):
        logger.info(f"Attempting to initialize GoogleBigQueryClient with credentials: {credentials_file}")
        try:
            client = GoogleBigQueryClient(credentials_path=credentials_file)

            # Check if client was initialized properly
            if not client.client:
                logger.error("Failed to initialize BigQuery client within the instance. Aborting test.")
                return

            logger.info(f"Fetching results for req_id: {req_id_to_test}")
            results = await client.fetch_results_by_req_id(req_id_to_test)

            if results:
                logger.info(f"Found {len(results)} matching row(s):")
                for row in results:
                    # Pretty print JSON if output is a string that looks like JSON, or if it's already parsed JSON
                    if 'output' in row and isinstance(row['output'], str):
                        try:
                            # Attempt to parse and pretty print if it's a JSON string
                            row['output'] = json.loads(row['output'])
                            logger.info(json.dumps(row, indent=2, default=str))  # default=str for datetime/timestamp
                        except json.JSONDecodeError:
                            logger.info(json.dumps(row, indent=2, default=str))  # Print as is if not valid JSON string
                    else:
                        # If output is already a Python dict (from JSON type in BQ) or not present
                        logger.info(json.dumps(row, indent=2, default=str))
            else:
                logger.info("No results found or an error occurred during fetch.")
        except ValueError as ve:
            logger.error(f"Configuration error during client initialization: {ve}")
        except FileNotFoundError as fnf:
            logger.error(f"Credentials file error: {fnf}")
        except Exception as e:
            logger.error(f"An unexpected error occurred during the test: {e}", exc_info=True)


    # Run the async main_test function
    asyncio.run(main_test(args.req_id, args.creds))
