import azure.functions as func
import logging
import pandas as pd # CSV processing library
import io # For reading CSV content from string
import json
import os
import csv
import re
import uuid
from datetime import datetime, timedelta, timezone
from azure.core.exceptions import ResourceNotFoundError
from azure.storage.blob import BlobServiceClient

app = func.FunctionApp()

# --- CONFIGURATION ---
SESSION_TIMEOUT = timedelta(minutes=15)
WORK_APPS_EXCEPTIONS = {
    "Atlassian", "Microsoft 365", "Microsoft Office Online", "Google Docs", "Microsoft Copilot", "Gmail", "Web-based Email", "Allow List, Web-based Email"
}
CONTEXTUAL_APPS_EXCEPTIONS = {
    "Spotify", "YouTube", "OpenAI ChatGPT", "Vimeo", "Udemy", "Wikipedia", "Streaming Video", "Allow List, Streaming Video"
}

# --- HELPER FUNCTIONS ---
def classify_activity(row: pd.Series) -> str:
    application_name = row['Application']
    blocked_categories = row['Blocked Categories']

    if application_name in WORK_APPS_EXCEPTIONS:
        return 'work'
    if application_name in CONTEXTUAL_APPS_EXCEPTIONS:
        return 'contextual'
    if not isinstance(blocked_categories, str) or not blocked_categories.strip():
        return 'non_work'

    categories = {cat.strip().lower() for cat in blocked_categories.split(',')}
    if 'allow list' in categories:
        return 'work' if len(categories) == 1 else 'contextual'
    return 'non_work'

def parse_datetime(date_str: str, time_str: str) -> datetime | None:
    formats_to_try = [
        '%d.%m.%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M:%S'
    ]
    for fmt in formats_to_try:
        try:
            return datetime.strptime(f"{date_str} {time_str}", fmt)
        except (ValueError, TypeError):
            continue
    logging.warning(f"Could not parse date-time: {date_str} {time_str}")
    return None

def calculate_work_sessions(df: pd.DataFrame) -> pd.DataFrame:
    df = df.sort_values(['Identities', 'Timestamp'])
    df['TimeDiff'] = df.groupby('Identities')['Timestamp'].diff()
    df['NewSession'] = (df['TimeDiff'] > SESSION_TIMEOUT) | (df['Identities'] != df['Identities'].shift())
    df['SessionID'] = df.groupby('Identities')['NewSession'].cumsum()

    work_sessions = df[df['ActivityType'] == 'work'].groupby(['Identities', 'SessionID']).size().reset_index()
    work_sessions = work_sessions[['Identities', 'SessionID']]
    work_sessions['IsWorkSession'] = True

    df = pd.merge(df, work_sessions, on=['Identities', 'SessionID'], how='left')
    df['IsWorkSession'] = df['IsWorkSession'].fillna(False)
    df.loc[(df['ActivityType'] == 'contextual') & (df['IsWorkSession']), 'ActivityType'] = 'contextual_work'

    return df

def process_csv_content(content: str) -> dict:
    try:
        dialect = csv.Sniffer().sniff(content[:4096])
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = ';' if content.count(';') > content.count(',') else ','

    df = pd.read_csv(
        io.StringIO(content),
        delimiter=delimiter,
        on_bad_lines='warn',
        engine='python',
        quoting=csv.QUOTE_MINIMAL
    )

    df.columns = [col.strip().replace('"', '') for col in df.columns]
    df['Timestamp'] = df.apply(
        lambda row: parse_datetime(str(row.get('Date')), str(row.get('Time'))),
        axis=1
    )
    df.dropna(subset=['Timestamp'], inplace=True)

    for col in ['Blocked Categories', 'Application', 'Application Category']:
        if col in df.columns:
            df[col].fillna('', inplace=True)
        else:
            df[col] = ''

    df['ActivityType'] = df.apply(classify_activity, axis=1)
    df = calculate_work_sessions(df)

    df = df.sort_values(['Identities', 'Timestamp'])
    df['TimeDiff'] = df.groupby('Identities')['Timestamp'].diff().shift(-1)
    df['Duration'] = df['TimeDiff'].apply(
        lambda x: x.total_seconds() / 60 if pd.notnull(x) and x <= SESSION_TIMEOUT else 0
    )

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

        for _, row in group.iterrows():
            activity_type = row['ActivityType']
            duration = row['Duration']
            key = {
                'work': "work_activity",
                'contextual_work': "contextual_work_activity",
                'non_work': "non_work_activity"
            }.get(activity_type)

            if duration > 0 and key:
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

        for key in daily_report:
            daily_report[key]["total_minutes"] = round(daily_report[key]["total_minutes"], 2)
            daily_report[key]["sites"].sort(key=lambda x: x["minutes"], reverse=True)

        reports[sanitized_id]["daily_reports"][date_str] = daily_report

    return reports

# --- BLOB TRIGGER FUNCTION ---
@app.blob_trigger(
    arg_name="myblob",
    path="rawdata/{name}",
    connection="timexdata_STORAGE"
)
def process_dns_logs(myblob: func.InputStream):
    logging.info(f"Processing blob: {myblob.name}")
    try:
        content = myblob.read().decode('utf-8-sig')
        reports = process_csv_content(content)
        save_reports_to_blob(reports)
    except Exception as e:
        logging.error(f"Processing failed: {str(e)}", exc_info=True)
        raise

def save_reports_to_blob(reports: dict):
    connection_string = os.getenv("timexdata_STORAGE")
    if not connection_string:
        raise ValueError("Storage connection string not configured")

    blob_service = BlobServiceClient.from_connection_string(connection_string)

    for sanitized_id, report_data in reports.items():
        blob_name = f"{sanitized_id}.json"
        blob_client = blob_service.get_blob_client(container="data", blob=blob_name)

        try:
            existing_data = json.loads(blob_client.download_blob().readall())
            existing_data["daily_reports"].update(report_data["daily_reports"])
            existing_data["report_updated_utc"] = report_data["report_updated_utc"]
            final_report = existing_data
        except ResourceNotFoundError:
            final_report = report_data

        blob_client.upload_blob(
            json.dumps(final_report, indent=2),
            overwrite=True
        )
        logging.info(f"Saved report to data/{blob_name}")

# --- HTTP TRIGGER FUNCTIONS ---
# Example: curl "https://processingtimex-cdhbdsdgfefqh6cj.germanywestcentral-01.azurewebsites.net/api/reports?identity=RUVT-KG57JT&daily_reports=2025-06-20"
# Example: curl "https://processingtimex-cdhbdsdgfefqh6cj.germanywestcentral-01.azurewebsites.net/api/reports" -X POST -H "Content-Type: application/json" -d '{"identity": "RUVT-KG57JT", "daily_reports": "2025-06-20"}'
# Example: curl "https://processingtimex-cdhbdsdgfefqh6cj.germanywestcentral-01.azurewebsites.net/api/reports" -X POST -F "file=@/path/to/your/file.csv"
@app.route(route="reports", auth_level=func.AuthLevel.ANONYMOUS, methods=["GET", "POST"])
def handle_reports(req: func.HttpRequest) -> func.HttpResponse:
    if req.method == "POST":
        content_type = req.headers.get('Content-Type', '')

        # Check if it's a file upload
        if 'multipart/form-data' in content_type:
            if not req.files:
                return func.HttpResponse(
                    json.dumps({"error": "No file uploaded"}),
                    mimetype="application/json",
                    status_code=400
                )
            return handle_file_upload(req)
        else:
            # Assume it's JSON
            try:
                req_body = req.get_json()
            except ValueError:
                # If not JSON, maybe it's form data
                try:
                    req_body = dict(req.form)
                except:
                    return func.HttpResponse(
                        json.dumps({"error": "Invalid request format"}),
                        mimetype="application/json",
                        status_code=400
                    )

            identity = req_body.get('identity')
            date = req_body.get('daily_reports')
            return get_report(identity, date)
    else:
        return handle_get_request(req)

def handle_get_request(req: func.HttpRequest) -> func.HttpResponse:
    identity = req.params.get("identity")
    date = req.params.get("daily_reports")
    return get_report(identity, date)

def handle_json_request(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        identity = req_body.get('identity')
        date = req_body.get('daily_reports')
        return get_report(identity, date)
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON format"}),
            mimetype="application/json",
            status_code=400
        )

def handle_file_upload(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Check if the request contains files
        if not req.files:
            return func.HttpResponse(
                json.dumps({"error": "No file uploaded"}),
                mimetype="application/json",
                status_code=400
            )

        # Get the first file (assuming only one file is uploaded)
        file = req.files.get('file')
        if not file:
            return func.HttpResponse(
                json.dumps({"error": "No file part with name 'file'"}),
                mimetype="application/json",
                status_code=400
            )

        # Read file content
        content = file.read().decode('utf-8-sig')

        # Process the content
        reports = process_csv_content(content)
        save_reports_to_blob(reports)

        identities = list(reports.keys())
        return func.HttpResponse(
            json.dumps({
                "message": "File processed successfully",
                "identities": identities,
                "count": len(identities)
            }),
            mimetype="application/json",
            status_code=200
        )
    except Exception as e:
        logging.error(f"File processing failed: {str(e)}", exc_info=True)
        return func.HttpResponse(
            json.dumps({"error": f"File processing failed: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )

def get_report(identity: str, date: str = None) -> func.HttpResponse:
    if not identity:
        return func.HttpResponse(
            json.dumps({"error": "Identity parameter is required"}),
            mimetype="application/json",
            status_code=400
        )

    connection_string = os.getenv("timexdata_STORAGE")
    if not connection_string:
        return func.HttpResponse(
            json.dumps({"error": "Storage connection not configured"}),
            mimetype="application/json",
            status_code=500
        )

    try:
        blob_service = BlobServiceClient.from_connection_string(connection_string)
        blob_client = blob_service.get_blob_client(
            container="data",
            blob=f"{identity}.json"
        )

        report_data = json.loads(blob_client.download_blob().readall())

        if date:
            if date in report_data["daily_reports"]:
                filtered_report = {
                    "identity": report_data["identity"],
                    "report_updated_utc": report_data["report_updated_utc"],
                    "daily_reports": {date: report_data["daily_reports"][date]}
                }
                return func.HttpResponse(
                    json.dumps(filtered_report, indent=2),
                    mimetype="application/json",
                    status_code=200
                )
            else:
                return func.HttpResponse(
                    json.dumps({"error": f"No data for date {date}"}),
                    mimetype="application/json",
                    status_code=404
                )

        return func.HttpResponse(
            json.dumps(report_data, indent=2),
            mimetype="application/json",
            status_code=200
        )

    except ResourceNotFoundError:
        return func.HttpResponse(
            json.dumps({"error": f"Report not found for {identity}"}),
            mimetype="application/json",
            status_code=404
        )
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": f"Internal error: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )

# --- GET IDENTITY FUNCTIONS ---
# Example curl "https://processingtimex-cdhbdsdgfefqh6cj.germanywestcentral-01.azurewebsites.net/api/identities"
@app.route(route="identities", auth_level=func.AuthLevel.ANONYMOUS, methods=["GET"])
def get_all_identities(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Fetching all identities from storage')

    connection_string = os.getenv("timexdata_STORAGE")
    if not connection_string:
        return func.HttpResponse(
            json.dumps({"error": "Storage connection not configured"}),
            mimetype="application/json",
            status_code=500
        )

    try:
        blob_service = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service.get_container_client("data")

        # Get a list of all JSON files in the ‘data’ container
        blob_list = container_client.list_blobs()

        # Extract file names (without the .json extension)
        identities = [blob.name.replace('.json', '') for blob in blob_list if blob.name.endswith('.json')]

        return func.HttpResponse(
            json.dumps({
                "count": len(identities),
                "identities": identities
            }),
            mimetype="application/json",
            status_code=200
        )

    except Exception as e:
        logging.error(f"Error fetching identities: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Failed to get identities: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )