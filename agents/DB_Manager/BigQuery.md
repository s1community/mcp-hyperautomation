# BigQuery Database Setup

This guide will walk you through setting up a BigQuery database for storing service responses. Even if you've never used Google Cloud before, following these steps will help you create and configure everything needed.

## Prerequisites

- A Google account
- Access to [Google Cloud Console](https://console.cloud.google.com/)

## Step 1: Create a Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Click the project dropdown at the top of the page
3. Click **"New Project"**
4. Enter a project name (e.g., "my-service-responses")
5. Click **"Create"**
6. Note your **Project ID** (e.g., `arcane-transit-457914-n8`) - you'll need this later

> **Note:** The Project ID is automatically generated and will be unique to your project. It may differ from your project name.

## Step 2: Enable the BigQuery API

1. In the Google Cloud Console, ensure your new project is selected
2. Navigate to **APIs & Services** > **Library** (or search for "APIs & Services" in the search bar)
3. Search for "BigQuery API"
4. Click on **"BigQuery API"**
5. Click **"Enable"**

## Step 3: Create a BigQuery Dataset

1. In the Google Cloud Console, navigate to **BigQuery** (search for "BigQuery" in the search bar)
2. In the BigQuery Explorer panel on the left, find your project ID
3. Click the three dots (**⋮**) next to your project name
4. Select **"Create dataset"**
5. Configure the dataset:
   - **Dataset ID:** `mcp_iso_results_dataset`
   - **Location type:** Choose based on your preference (recommend "US" for multi-region)
   - **Default table expiration:** Leave unchecked (or set as needed)
6. Click **"Create dataset"**

## Step 4: Create the Table Schema

1. In the BigQuery Explorer, expand your project and find the `mcp_iso_results_dataset` dataset
2. Click the three dots (**⋮**) next to the dataset name
3. Select **"Create table"**
4. Configure the table:
   - **Source:** Empty table
   - **Destination:**
     - **Dataset:** `mcp_iso_results_dataset` (should be pre-filled)
     - **Table:** `ha_service_responses`
   - **Schema:** Click **"Add field"** and add the following fields:

| Field name  | Type      | Mode     |
|-------------|-----------|----------|
| time_start  | TIMESTAMP | REQUIRED |
| time_stop   | TIMESTAMP | REQUIRED |
| req_id      | STRING    | REQUIRED |
| action      | STRING    | REQUIRED |
| output      | JSON      | NULLABLE |

5. Click **"Create table"**

### Alternative: Create Table Using SQL

You can also create the table using SQL in the BigQuery query editor:

```sql
CREATE TABLE `mcp_iso_results_dataset.ha_service_responses` (
  time_start TIMESTAMP NOT NULL,
  time_stop TIMESTAMP NOT NULL,
  req_id STRING NOT NULL,
  action STRING NOT NULL,
  output JSON
);
```

## Step 5: Create a Service Account

A service account allows your application to authenticate and access BigQuery programmatically.

1. In the Google Cloud Console, navigate to **IAM & Admin** > **Service Accounts**
2. Click **"Create Service Account"**
3. Configure the service account:
   - **Service account name:** `bigquery-api-access` (or any descriptive name)
   - **Service account description:** "Service account for BigQuery API access"
4. Click **"Create and Continue"**

## Step 6: Grant BigQuery Permissions

1. In the **"Grant this service account access to project"** section, add the following roles:
   - **BigQuery Data Editor** (allows reading and writing data)
   - **BigQuery Job User** (allows running queries)
2. Click **"Continue"**
3. Skip the "Grant users access to this service account" section
4. Click **"Done"**

> **Why these roles?**
> - **BigQuery Data Editor:** Enables reading from and writing to BigQuery tables
> - **BigQuery Job User:** Enables creating and running query jobs

## Step 7: Generate Service Account Credentials (JSON Key)

1. On the **Service Accounts** page, find the service account you just created
2. Click on the service account email address
3. Go to the **"Keys"** tab
4. Click **"Add Key"** > **"Create new key"**
5. Select **"JSON"** as the key type
6. Click **"Create"**
7. A JSON file will be downloaded to your computer - **keep this file secure!**

The JSON file will look like this:

```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "8e569cb7ff7c4475f15...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "client_email": "bigquery-api-access@your-project-id.iam.gserviceaccount.com",
  "client_id": "123456789...",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/..."
}
```

> **Security Warning:** Never commit this JSON file to version control (Git). Add it to your `.gitignore` file.

## Step 8: Configure Environment Variables

Set up the following environment variables in your application:

```bash
# Your unique Google Cloud Project ID
GOOGLE_CLOUD_PROJECT="your-project-id"

# BigQuery dataset name
BIGQUERY_DATASET_ID="mcp_iso_results_dataset"

# BigQuery table name
BIGQUERY_TABLE_ID="ha_service_responses"

# Column name for request ID
BIGQUERY_REQ_ID_COLUMN="req_id"

# Path to your service account JSON credentials file
GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/credentials.json"
```

### Example `.env` file:

```
GOOGLE_CLOUD_PROJECT=arcane-transit-457914-n8
BIGQUERY_DATASET_ID=mcp_iso_results_dataset
BIGQUERY_TABLE_ID=ha_service_responses
BIGQUERY_REQ_ID_COLUMN=req_id
GOOGLE_APPLICATION_CREDENTIALS=./credentials/bigquery-credentials.json
```

