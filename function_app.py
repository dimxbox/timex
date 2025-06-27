import azure.functions as func
import logging
import pandas as pd
import io
import json
import os
import csv
import re
from datetime import datetime, timedelta, timezone
from azure.core.exceptions import ResourceNotFoundError
from azure.storage.blob import BlobServiceClient


# Create a FunctionApp instance
app = func.FunctionApp()


# --- CONFIGURATION ---
# Define the inactivity timeout to consider a session closed.
SESSION_TIMEOUT = timedelta(minutes=15)


# --- APPLICATION-SPECIFIC EXCEPTIONS ---
# Lists of applications to be classified regardless of their 'Blocked Categories' value.
# This handles cases where work-related apps don't have a category assigned.
WORK_APPS_EXCEPTIONS = {
   "Atlassian",
   "Microsoft 365",
   "Microsoft Office Online",
   "Web-based Email",
   "Allow List, Web-based Email",
   "Gmail"
}
CONTEXTUAL_APPS_EXCEPTIONS = {
   "Spotify",
   "YouTube",
   "ChatGPT",
   "Streaming Video",
   "Allow List, Streaming Video"
}


# --- HELPER FUNCTIONS ---


def classify_activity(row: pd.Series) -> str:
   """
   Classifies the activity type based on the application name and 'Blocked Categories'.
   It first checks for application-based exceptions, then falls back to category logic.

   Args:
       row: A pandas Series representing a single row from the DataFrame.

   Returns:
       A string representing the activity type: 'work', 'contextual', or 'non_work'.
   """
   application_name = row['Application']
   blocked_categories = row['Blocked Categories']

   # 1. Check for application-based exceptions first.
   if application_name in WORK_APPS_EXCEPTIONS:
       return 'work'
   if application_name in CONTEXTUAL_APPS_EXCEPTIONS:
       return 'contextual'

   # 2. Fallback to category-based logic if no exception matches.
   if not isinstance(blocked_categories, str) or not blocked_categories.strip():
       # Treat empty or NaN categories as non-work/technical traffic.
       return 'non_work'

   # Normalize the string for consistent matching.
   categories = {cat.strip().lower() for cat in blocked_categories.split(',')}

   if 'allow list' in categories:
       # If 'allow list' is the *only* category, it's direct work activity.
       if len(categories) == 1:
           return 'work'
       else:
           # If 'allow list' is combined with others, it's contextual work activity.
           return 'contextual'

   # If 'allow list' is not present, it's non-work activity.
   return 'non_work'


def parse_datetime(date_str: str, time_str: str) -> datetime | None:
   """
   Parses date and time strings from various possible formats into a datetime object.

   Args:
       date_str: The date part of the timestamp.
       time_str: The time part of the timestamp.

   Returns:
       A datetime object if parsing is successful, otherwise None.
   """
   # List of expected datetime formats to handle inconsistencies in logs.
   formats_to_try = [
       '%d.%m.%Y %H:%M:%S',  # Format like '20.06.2025 8:59:03'
       '%Y-%m-%d %H:%M:%S',  # Format like '2025-03-21 16:24:01'
       '%m/%d/%Y %H:%M:%S'   # Another common format
   ]
  
   for fmt in formats_to_try:
       try:
           return datetime.strptime(f"{date_str} {time_str}", fmt)
       except (ValueError, TypeError):
           continue
   # Return None if no format matches.
   logging.warning(f"Could not parse date-time: {date_str} {time_str}")
   return None


def calculate_work_sessions(df: pd.DataFrame) -> pd.DataFrame:
    """
    Identifies work sessions and marks contextual activities that occur during these sessions.
    
    Args:
        df: DataFrame containing all DNS log entries
        
    Returns:
        DataFrame with additional 'InWorkSession' column indicating if activity occurred during a work session
    """
    # Sort by identity and timestamp
    df = df.sort_values(['Identities', 'Timestamp'])
    
    # Calculate time differences between consecutive entries
    df['TimeDiff'] = df.groupby('Identities')['Timestamp'].diff()
    
    # Identify session boundaries (gaps > SESSION_TIMEOUT)
    df['NewSession'] = (df['TimeDiff'] > SESSION_TIMEOUT) | (df['Identities'] != df['Identities'].shift())
    
    # Create session IDs
    df['SessionID'] = df.groupby('Identities')['NewSession'].cumsum()
    
    # Identify sessions that contain any work activity
    work_sessions = df[df['ActivityType'] == 'work'].groupby(['Identities', 'SessionID']).size().reset_index()
    work_sessions = work_sessions[['Identities', 'SessionID']]
    work_sessions['IsWorkSession'] = True
    
    # Merge work session info back to original dataframe
    df = pd.merge(df, work_sessions, on=['Identities', 'SessionID'], how='left')
    df['IsWorkSession'] = df['IsWorkSession'].fillna(False)
    
    # Reclassify contextual activities that occurred during work sessions
    df.loc[(df['ActivityType'] == 'contextual') & (df['IsWorkSession']), 'ActivityType'] = 'contextual_work'
    
    return df


# --- MAIN AZURE FUNCTION ---


@app.blob_trigger(
   arg_name="myblob",
   path="rawdata/{name}",
   connection="timexdata_STORAGE"
)
def process_dns_logs(myblob: func.InputStream):
   """
   This function is triggered when a new blob is created in the 'rawdata' container.
   It processes DNS log files, calculates time spent, and saves a JSON report.
   """
   logging.info(f"Processing blob: {myblob.name}")
   try:
       # --- 1. Read and Parse CSV Data from Blob ---
       content = myblob.read().decode('utf-8-sig')
      
       try:
           dialect = csv.Sniffer().sniff(content[:4096])
           delimiter = dialect.delimiter
       except csv.Error:
           delimiter = ';' if content.count(';') > content.count(',') else ','
       logging.info(f"Detected delimiter: '{delimiter}'")

       df = pd.read_csv(
           io.StringIO(content),
           delimiter=delimiter,
           on_bad_lines='warn',
           engine='python',
           quoting=csv.QUOTE_MINIMAL
       )
      
       df.columns = [col.strip().replace('"', '') for col in df.columns]

       # --- 2. Pre-process Data ---
       df['Timestamp'] = df.apply(
           lambda row: parse_datetime(str(row.get('Date')), str(row.get('Time'))),
           axis=1
       )
       df.dropna(subset=['Timestamp'], inplace=True)
       if df.empty:
           logging.warning("DataFrame is empty after parsing timestamps. Aborting.")
           return

       for col in ['Blocked Categories', 'Application', 'Application Category']:
           if col in df.columns:
               df[col].fillna('', inplace=True)
           else:
               df[col] = ''
      
       # Initial classification of activities
       df['ActivityType'] = df.apply(classify_activity, axis=1)
      
       # Identify work sessions and reclassify contextual activities during work sessions
       df = calculate_work_sessions(df)
      
       # --- 3. Calculate Session Durations ---
       df = df.sort_values(['Identities', 'Timestamp'])
       df['TimeDiff'] = df.groupby('Identities')['Timestamp'].diff().shift(-1)
       df['Duration'] = df['TimeDiff'].apply(
           lambda x: x.total_seconds() / 60
           if pd.notnull(x) and x <= SESSION_TIMEOUT
           else 0
       )

       # --- 4. Generate Reports per Device and Date ---
       reports = {}
       for (identity, date), group in df.groupby(['Identities', pd.Grouper(key='Timestamp', freq='D')]):
           sanitized_id = re.sub(r'[?<>:"/\\|*]', '', identity)
           date_str = date.strftime('%Y-%m-%d')
          
           if sanitized_id not in reports:
               reports[sanitized_id] = {
                   "identity": identity,
                   "report_updated_utc": datetime.now(timezone.utc).isoformat(),
                   "daily_reports": {}
               }
          
           daily_report = {
               "work_activity": {"total_minutes": 0, "sites": []},
               "contextual_work_activity": {"total_minutes": 0, "sites": []},
               "non_work_activity": {"total_minutes": 0, "sites": []}
           }
          
           # Process each activity type
           for _, row in group.iterrows():
               activity_type = row['ActivityType']
               duration = row['Duration']
               
               if activity_type == 'work':
                   key = "work_activity"
               elif activity_type == 'contextual_work':
                   key = "contextual_work_activity"
               else:
                   key = "non_work_activity"
               
               if duration > 0:
                   # Find if this site already exists in the report
                   site_exists = False
                   for site in daily_report[key]["sites"]:
                       if (site["Application"] == row['Application'] and 
                           site["Application Category"] == row['Application Category'] and 
                           site["Blocked Categories"] == row['Blocked Categories']):
                           site["minutes"] = round(site["minutes"] + duration, 2)
                           site_exists = True
                           break
                   
                   if not site_exists:
                       daily_report[key]["sites"].append({
                           "Application": row['Application'],
                           "Application Category": row['Application Category'],
                           "Blocked Categories": row['Blocked Categories'],
                           "minutes": round(duration, 2)
                       })
                   
                   daily_report[key]["total_minutes"] += duration
          
           # Round the totals
           for key in daily_report:
               daily_report[key]["total_minutes"] = round(daily_report[key]["total_minutes"], 2)
               # Sort sites by minutes descending
               daily_report[key]["sites"].sort(key=lambda x: x["minutes"], reverse=True)

           reports[sanitized_id]["daily_reports"][date_str] = daily_report

       # --- 5. Save Reports to Blob Storage ---
       connection_string = os.getenv("timexdata_STORAGE")
       if not connection_string:
           logging.error("Storage connection string is not set.")
           return
          
       blob_service = BlobServiceClient.from_connection_string(connection_string)
      
       for sanitized_id, report_data in reports.items():
           blob_name = f"{sanitized_id}.json"
           blob_client = blob_service.get_blob_client(container="data", blob=blob_name)
          
           try:
               existing_data_blob = blob_client.download_blob()
               existing_data = json.loads(existing_data_blob.readall())
              
               existing_data["daily_reports"].update(report_data["daily_reports"])
               existing_data["report_updated_utc"] = report_data["report_updated_utc"]
               final_report = existing_data
               logging.info(f"Merging new data into existing report for {sanitized_id}")

           except ResourceNotFoundError:
               final_report = report_data
               logging.info(f"Creating new report for {sanitized_id}")

           blob_client.upload_blob(
               json.dumps(final_report, indent=2),
               overwrite=True
           )
           logging.info(f"Successfully saved report to data/{blob_name}")

   except Exception as e:
       logging.error(f"Processing failed for blob {myblob.name}: {str(e)}", exc_info=True)
       raise


@app.route(route="reports", auth_level=func.AuthLevel.ANONYMOUS, methods=["GET", "POST"])
def get_time_report(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing report request')

    # Try to get JSON from request body for POST
    if req.method == "POST":
        try:
            req_body = req.get_json()
        except ValueError:
            return func.HttpResponse(
                "Invalid JSON format in request body",
                status_code=400
            )
    else:  # GET request - get params from query string
        req_body = {
            "identity": req.params.get("identity"),
            "daily_reports": req.params.get("daily_reports")
        }

    # Check required identity parameter
    identity = req_body.get('identity')
    if not identity:
        return func.HttpResponse(
            "Identity parameter is required",
            status_code=400
        )

    # Get optional date parameter
    requested_date = req_body.get('daily_reports')

    # Connect to Blob Storage
    connection_string = os.getenv("timexdata_STORAGE")
    if not connection_string:
        return func.HttpResponse(
            "Storage connection string not configured",
            status_code=500
        )

    try:
        # Load report from Blob Storage
        blob_service = BlobServiceClient.from_connection_string(connection_string)
        blob_client = blob_service.get_blob_client(
            container="data",
            blob=f"{identity}.json"
        )
        
        report_data = json.loads(blob_client.download_blob().readall())

        # Filter by date if specified
        if requested_date:
            if requested_date in report_data["daily_reports"]:
                filtered_report = {
                    "identity": report_data["identity"],
                    "report_updated_utc": report_data["report_updated_utc"],
                    "daily_reports": {
                        requested_date: report_data["daily_reports"][requested_date]
                    }
                }
                return func.HttpResponse(
                    json.dumps(filtered_report, indent=2),
                    mimetype="application/json",
                    status_code=200
                )
            else:
                return func.HttpResponse(
                    json.dumps({"error": f"No data found for date {requested_date}"}),
                    mimetype="application/json",
                    status_code=404
                )
        
        # Return all data if no date specified
        return func.HttpResponse(
            json.dumps(report_data, indent=2),
            mimetype="application/json",
            status_code=200
        )

    except ResourceNotFoundError:
        return func.HttpResponse(
            json.dumps({"error": f"Report not found for identity '{identity}'"}),
            mimetype="application/json",
            status_code=404
        )
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Internal server error: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )