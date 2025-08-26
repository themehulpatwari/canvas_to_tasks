import traceback
import logging
from pymongo.mongo_client import MongoClient
from datetime import datetime
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import os
from dotenv import load_dotenv
from util import get_ics_events, sync_with_tasklist

load_dotenv()

app_config = {
    "OAUTH_CLIENT_ID": os.getenv("OAUTH_CLIENT_ID"),
    "OAUTH_CLIENT_SECRET": os.getenv("OAUTH_CLIENT_SECRET"),
    "OAUTH_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": os.getenv("FLASK_SECRET"),
    "FLASK_PORT": int(os.getenv("FLASK_PORT", 3000)),
    "MONGO_DB_PASS": os.getenv("MONGO_DB_PASS"),
    "MONGO_DB_USER": os.getenv("MONGO_DB_USER"),
    "MONGO_DB_NAME": os.getenv("MONGO_DB_NAME"),
}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("one_time_sync.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("one_time_sync")

# MongoDB connection settings - using app_config values
MONGO_URI = f"mongodb+srv://{app_config['MONGO_DB_USER']}:{app_config['MONGO_DB_PASS']}@{app_config['MONGO_DB_NAME']}.u1cau2u.mongodb.net/?retryWrites=true&w=majority&appName={app_config['MONGO_DB_NAME']}"


def connect_to_mongodb():
    """Establish connection to MongoDB and return db object"""
    try:
        logger.info("Connecting to MongoDB...")
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')  # Verify connection
        db = client.dotuser  # Use your actual database name
        logger.info("MongoDB connection successful!")
        return db
    except Exception as e:
        logger.error(f"MongoDB connection failed: {str(e)}")
        return None


def refresh_user_tokens(user_auth):
    """Refresh the access token using the refresh token"""
    try:
        # Build the credentials object
        creds = Credentials(
            token=None,  # We don't have a valid token
            refresh_token=user_auth.get('refresh_token'),
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
    except Exception as e:
        logger.error(f"Error refreshing tokens: {str(e)}")
        return None


def sync_task_for_user(user_auth, user_link):
    """Sync tasks for a specific user"""
    try:
        # Get user information
        email = user_auth.get('email')
        ics_url = user_link.get('ics_url')
        
        if not ics_url:
            logger.warning(f"No ICS URL found for user {email}")
            return False
        
        logger.info(f"Starting sync for user {email} with calendar {ics_url}")
        
        # Refresh the user's tokens
        oauth_token = refresh_user_tokens(user_auth)
        if not oauth_token:
            logger.error(f"Failed to refresh tokens for user {email}")
            return False
            
        # Get calendar events
        events = get_ics_events(ics_url)
        if not events:
            logger.warning(f"No events found in calendar for user {email}")
            return False
            
        # Sync with Google Tasks - don't include past events
        result = sync_with_tasklist(oauth_token, events, include_past_events=False)
        
        if result.get('success'):
            logger.info(f"Sync successful for {email}. Added {result.get('task_count')} tasks.")
            return True
        else:
            logger.error(f"Sync failed for {email}: {result.get('error')}")
            return False
            
    except Exception as e:
        logger.error(f"Error during sync for user: {str(e)}")
        logger.error(traceback.format_exc())
        return False


def run_one_time_sync():
    """Perform a one-time sync for all users in the database"""
    logger.info("Starting one-time sync for all users")
    
    db = connect_to_mongodb()
    if db is None:
        logger.error("Cannot connect to database. Aborting sync.")
        return
    
    # Get all users with auth information and ics links
    try:
        users_auth = list(db.user_auth.find())
        users_links = list(db.user_links.find())
        
        # Create a map of email to ics_url for quick lookup
        links_map = {user['email']: user for user in users_links}
        
        logger.info(f"Found {len(users_auth)} users with auth data and {len(users_links)} with calendar links")
        
        if len(users_auth) == 0:
            logger.info("No users found to sync.")
            return
        
        sync_count = 0
        failed_count = 0
        
        for user_auth in users_auth:
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
            else:
                logger.warning(f"No calendar link found for user {email}")
                failed_count += 1
        
        logger.info(f"One-time sync completed.")
        logger.info(f"Successfully synced: {sync_count} users")
        logger.info(f"Failed to sync: {failed_count} users")
        logger.info(f"Total users processed: {len(users_auth)}")
    
    except Exception as e:
        logger.error(f"Error during one-time sync: {str(e)}")
        logger.error(traceback.format_exc())


if __name__ == "__main__":
    logger.info("Starting one-time sync process")
    run_one_time_sync()
    logger.info("One-time sync process completed")
