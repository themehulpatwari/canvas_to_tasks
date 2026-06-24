import time
import logging
from ratelimit import limits, sleep_and_retry
from pymongo.mongo_client import MongoClient
from datetime import datetime
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import os
from dotenv import load_dotenv
from util import get_ics_events, sync_with_tasklist, decrypt_token

# Silence all logging (including from util.py) for the one-time sync run.
logging.disable(logging.CRITICAL)

load_dotenv()

app_config = {
    "OAUTH_CLIENT_ID": os.getenv("OAUTH_CLIENT_ID"),
    "OAUTH_CLIENT_SECRET": os.getenv("OAUTH_CLIENT_SECRET"),
    "OAUTH_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": os.getenv("FLASK_SECRET"),
    "FLASK_PORT": int(os.getenv("FLASK_PORT", 3000)),
    "MONGO_URI": os.getenv("MONGO_URI"),
    "MONGO_DB_NAME": os.getenv("MONGO_DB_NAME", "dotuser"),
}

# Full MongoDB connection string from the environment (set in CI secrets).
MONGO_URI = app_config['MONGO_URI']

# Rate limiting constants
GOOGLE_API_CALLS_PER_MINUTE = 300  # Google Tasks API quota
ICS_FETCH_CALLS_PER_MINUTE = 30    # Be gentle with ICS endpoints


def connect_to_mongodb():
    """Establish connection to MongoDB and return db object"""
    if not MONGO_URI:
        return None
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')  # Verify connection
        db = client[app_config['MONGO_DB_NAME']]
        return db
    except Exception:
        return None


@sleep_and_retry
@limits(calls=GOOGLE_API_CALLS_PER_MINUTE, period=60)
def refresh_user_tokens(user_auth):
    """Refresh the access token using the refresh token"""
    try:
        # Build the credentials object
        creds = Credentials(
            token=None,  # We don't have a valid token
            refresh_token=decrypt_token(user_auth.get('refresh_token')),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=app_config['OAUTH_CLIENT_ID'],
            client_secret=app_config['OAUTH_CLIENT_SECRET'],
            scopes=["https://www.googleapis.com/auth/tasks"]
        )
        
        # Request a new token
        creds.refresh(Request())
        
        # Return the refreshed credentials
        return {
            "access_token": creds.token,
            "refresh_token": creds.refresh_token,
            "client_id": user_auth.get('client_id'),
            "client_secret": user_auth.get('client_secret'),
        }
    except Exception:
        return None


@sleep_and_retry
@limits(calls=ICS_FETCH_CALLS_PER_MINUTE, period=60)
def sync_task_for_user(user_auth, user_link):
    """Sync tasks for a specific user"""
    try:
        ics_url = user_link.get('ics_url')

        if not ics_url:
            return False

        # Refresh the user's tokens
        oauth_token = refresh_user_tokens(user_auth)
        if not oauth_token:
            return False

        # Get calendar events
        events = get_ics_events(ics_url)
        if not events:
            return False

        # Sync with Google Tasks - don't include past events
        result = sync_with_tasklist(oauth_token, events, include_past_events=False)

        return bool(result.get('success'))

    except Exception:
        return False


def run_one_time_sync():
    """Perform a one-time sync for all users in the database"""
    db = connect_to_mongodb()
    if db is None:
        print("Cannot connect to database. Aborting sync.")
        return

    # Get all users with auth information and ics links
    try:
        users_auth = list(db.user_auth.find())
        users_links = list(db.user_links.find())

        # Create a map of email to ics_url for quick lookup
        links_map = {user['email']: user for user in users_links}

        total_users = len(users_auth)
        if total_users == 0:
            print("No users found to sync.")
            return

        print(f"Found {total_users} users to process")

        sync_count = 0
        failed_count = 0

        for index, user_auth in enumerate(users_auth, start=1):
            print(f"Processing user {index}/{total_users}")
            email = user_auth.get('email')
            user_link = links_map.get(email)

            if user_link:
                success = sync_task_for_user(user_auth, user_link)
                if success:
                    sync_count += 1

                    # Update last_sync timestamp in database
                    db.user_auth.update_one(
                        {"email": email},
                        {"$set": {"last_sync": datetime.now()}}
                    )
                else:
                    failed_count += 1

                # Add a small delay between users to avoid overwhelming APIs
                time.sleep(1)
            else:
                failed_count += 1

        print(f"Successfully synced: {sync_count} users")
        print(f"Failed to sync: {failed_count} users")
        print(f"Total users processed: {total_users}")

    except Exception:
        print("Error during one-time sync.")


if __name__ == "__main__":
    run_one_time_sync()
