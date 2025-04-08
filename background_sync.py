import time
import schedule
from pymongo.mongo_client import MongoClient
from datetime import datetime
import traceback
import logging
import requests
from google.oauth2.credentials import Credentials
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from util import get_ics_events, sync_with_tasklist

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("background_sync.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("background_sync")

# MongoDB connection settings
MONGO_DB_PASS = "svkSnyNOAw32fHo0"  # Consider using environment variables
MONGO_URI = f"mongodb+srv://themehulpatwari:{MONGO_DB_PASS}@dotuser.u1cau2u.mongodb.net/?retryWrites=true&w=majority&appName=dotuser"


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
            client_id=user_auth.get('client_id'),
            client_secret=user_auth.get('client_secret'),
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


def sync_all_users():
    """Sync tasks for all users in the database"""
    logger.info("Starting scheduled sync for all users")
    
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
        
        sync_count = 0
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
        
        logger.info(f"Sync completed. Successfully synced {sync_count}/{len(users_auth)} users.")
    
    except Exception as e:
        logger.error(f"Error during sync_all_users: {str(e)}")
        logger.error(traceback.format_exc())


def run_scheduler():
    """Run the scheduler that triggers sync every hour"""
    # Schedule the sync to run every hour
    schedule.every(1).hours.do(sync_all_users)
    
    logger.info("Background sync scheduler started. Will sync every hour.")
    
    # Run once immediately on startup
    sync_all_users()
    
    # Keep running indefinitely
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute if there's a scheduled task to run


if __name__ == "__main__":
    # Import the required Google auth modules here to avoid module not found errors
    from google.auth.transport.requests import Request
    
    logger.info("Starting background sync process")
    run_scheduler()
