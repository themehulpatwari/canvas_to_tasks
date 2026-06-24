from flask import Flask, redirect, render_template, session, url_for, request, flash
from authlib.integrations.flask_client import OAuth
import json
import logging
from util import get_ics_events, sync_with_tasklist, encrypt_token
from datetime import datetime
import os
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("server")

# Generic message shown to users; details go to the server log only, never to
# the client (raw exceptions can embed the Mongo connection string/password).
GENERIC_DB_ERROR = "A database error occurred. Please try again later."

app_config = {
    "OAUTH_CLIENT_ID": os.getenv("OAUTH_CLIENT_ID"),
    "OAUTH_CLIENT_SECRET": os.getenv("OAUTH_CLIENT_SECRET"),
    "OAUTH_META_URL": "https://accounts.google.com/.well-known/openid-configuration",
    "FLASK_SECRET": os.getenv("FLASK_SECRET"),
    "FLASK_PORT": int(os.getenv("FLASK_PORT", 3000)),
    "MONGO_DB_PASS": os.getenv("MONGO_DB_PASS"),
    "MONGO_DB_USER": os.getenv("MONGO_DB_USER", "themehulpatwari"),
    "MONGO_DB_NAME": os.getenv("MONGO_DB_NAME", "dotuser"),
}

app = Flask(__name__)

app.secret_key = app_config['FLASK_SECRET']

# Harden the session cookie. Secure is enabled outside local development so
# the cookie is never sent over plain HTTP; HttpOnly keeps it out of JS;
# SameSite=Lax blocks it on cross-site POSTs (defence-in-depth with CSRF).
_is_dev = os.getenv("FLASK_ENV") == "development"
app.config.update(
    SESSION_COOKIE_NAME='my_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=not _is_dev,
)

# MongoDB connection setup
mongo_client = None
db = None
mongo_uri = None

try:
    # Setup MongoDB connection
    mongo_password = app_config['MONGO_DB_PASS']
    mongo_user = app_config['MONGO_DB_USER']
    mongo_db_name = app_config['MONGO_DB_NAME']
    mongo_uri = f"mongodb+srv://{mongo_user}:{mongo_password}@dotuser.u1cau2u.mongodb.net/?retryWrites=true&w=majority&appName={mongo_db_name}"
    
    mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    
    # Send a ping to confirm connection
    mongo_client.admin.command('ping')
    
    # Set the database
    db = mongo_client[mongo_db_name]
    
    # Log database connection status
    if os.getenv("FLASK_ENV") == "development":
        db_list = mongo_client.list_database_names()
        print(f"Connected to MongoDB. Available databases: {', '.join(db_list)}")
        
except Exception as e:
    print(f"MongoDB connection failed: {e}")

# Store sessions server-side (in MongoDB) instead of in the client cookie, so
# the OAuth token (incl. the long-lived refresh token) never leaves the server.
# The cookie then only carries a signed session id. Falls back to the default
# (now hardened) cookie session if Mongo is unavailable.
if db is not None:
    try:
        from flask_session import Session
        app.config.update(
            SESSION_TYPE='mongodb',
            SESSION_MONGODB=mongo_client,
            SESSION_MONGODB_DB=app_config['MONGO_DB_NAME'],
            SESSION_MONGODB_COLLECT='sessions',
            SESSION_PERMANENT=False,
            SESSION_USE_SIGNER=True,
        )
        Session(app)
        logger.info("Server-side sessions enabled (MongoDB backend)")
    except Exception as e:
        logger.error(f"Falling back to cookie sessions; Flask-Session init failed: {e}")

# Trust one layer of reverse proxy (gunicorn/host) so request.remote_addr
# reflects the real client IP for rate limiting and cookie handling.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# CSRF protection for all state-changing POST forms (sync_calendar, delete_link).
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Rate limiting to curb abuse of the outbound-fetching sync endpoint and login.
# Use MongoDB as shared storage so limits are enforced across all gunicorn
# workers/dynos (in-memory storage would be per-process). Falls back to
# in-memory if Mongo is unavailable so the app still starts.
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

_limiter_storage = mongo_uri if (db is not None and mongo_uri) else "memory://"
try:
    limiter = Limiter(
        key_func=get_remote_address, app=app,
        default_limits=[], storage_uri=_limiter_storage,
    )
    if _limiter_storage != "memory://":
        logger.info("Rate limiting using shared MongoDB storage")
except Exception as e:
    logger.error(f"Rate-limit Mongo storage init failed ({e}); using in-memory")
    limiter = Limiter(
        key_func=get_remote_address, app=app,
        default_limits=[], storage_uri="memory://",
    )

@app.errorhandler(429)
def ratelimit_handler(e):
    flash('Too many requests. Please wait a moment and try again.', 'error')
    return redirect(url_for('home'))

oauth = OAuth(app)

oauth.register(
    name='google',
    client_id=app_config['OAUTH_CLIENT_ID'],
    client_secret=app_config['OAUTH_CLIENT_SECRET'],
    server_metadata_url=app_config['OAUTH_META_URL'],
    client_kwargs={
        'scope': ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/tasks', 'https://www.googleapis.com/auth/tasks.readonly'],
    }
)

@app.route('/')
def home():
    # Check if user is logged in
    if session.get('user'):
        # Get user's email from session
        user_email = session.get('user', {}).get('userinfo', {}).get('email')
        
        saved_link = None
        if user_email and db is not None:
            try:
                # Check if user has a saved ICS link
                user_data = db.user_links.find_one({"email": user_email})
                if user_data and user_data.get("ics_url"):
                    saved_link = user_data.get("ics_url")
                else:
                    flash('You don\'t have any saved calendar link yet.', 'info')
            except Exception as e:
                flash(GENERIC_DB_ERROR, 'error')
                logger.error(f"MongoDB error: {e}")
        else:
            if session.get('user'):  # Only show this message if logged in
                flash('No saved calendar link found. Please enter a new ICS URL.', 'info')
        
        # Only pass saved_link to template if it's not None
        template_vars = {"session": session.get("user")}
        if saved_link:
            template_vars['saved_link'] = saved_link
            
        return render_template('home.html', **template_vars)
    
    return render_template('home.html', session=session.get("user"))

@app.route('/login')
@limiter.limit("20 per minute")
def login():
    redirect_uri = url_for('auth', _external=True)
    return oauth.google.authorize_redirect(
        redirect_uri,
        access_type='offline',  # Enable offline access for refresh tokens
        include_granted_scopes='true'  # Enable incremental authorization
    )

@app.route('/auth')
def auth():
    token = oauth.google.authorize_access_token()
    session['user'] = token
    
    # Store authentication information in MongoDB
    if db is not None and token.get('userinfo') and token.get('userinfo').get('email'):
        try:
            user_email = token['userinfo']['email']
            
            # Create update data dictionary
            update_data = {
                "email": user_email,
                "last_updated": datetime.now()
            }
            
            # Only include refresh_token in the update if it's present.
            # Encrypt it at rest so a DB compromise doesn't expose usable creds.
            if token.get('refresh_token'):
                update_data["refresh_token"] = encrypt_token(token.get('refresh_token'))
            
            # Store OAuth token information in the database
            db.user_auth.update_one(
                {"email": user_email},
                {"$set": update_data},
                upsert=True
            )

            print(f"OAuth tokens saved for {user_email}")
        except Exception as e:
            logger.error(f"Error saving OAuth tokens: {e}")
    
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/import_ics', methods=['GET'])
def import_ics():
    # Check if user is logged in
    if not session.get('user'):
        flash('Please log in to import calendar events', 'error')
        return redirect(url_for('home'))
    
    # Get user's email from session
    user_email = session.get('user', {}).get('userinfo', {}).get('email')
    
    saved_link = None
    if user_email and db is not None:  # Fixed: proper check for database object
        try:
            # Check if user has a saved ICS link
            user_data = db.user_links.find_one({"email": user_email})
            if user_data and user_data.get("ics_url"):
                saved_link = user_data.get("ics_url")
            else:
                flash('You don\'t have any saved calendar link yet.', 'info')
        except Exception as e:
            flash(GENERIC_DB_ERROR, 'error')
            logger.error(f"MongoDB error: {e}")
    else:
        flash('No saved calendar link found. Please enter a new ICS URL.', 'info')
    
    # Only pass saved_link to template if it's not None
    template_vars = {}
    if saved_link:
        template_vars['saved_link'] = saved_link
        
    return render_template('import_ics.html', **template_vars)

@app.route('/sync_calendar', methods=['POST'])
@limiter.limit("10 per minute")
def sync_calendar():
    # Check if user is logged in
    if not session.get('user'):
        flash('Please log in to sync Canvas calendar events', 'error')
        return redirect(url_for('home'))
    
    ics_url = request.form.get('ics_url')
    
    if not ics_url:
        flash('Please provide your Canvas ICS URL', 'error')
        return render_template('import_ics.html')
        
    try:
        # Get events from ICS URL
        events = get_ics_events(ics_url)
        
        if not events:
            flash('No events found in the provided Canvas ICS file', 'warning')
            return render_template('import_ics.html')
        
        # Save or update the ICS URL in the database
        user_email = session.get('user', {}).get('userinfo', {}).get('email')
        if user_email and db is not None:  # Fixed: proper check for database object
            try:
                db.user_links.update_one(
                    {"email": user_email},
                    {"$set": {
                        "email": user_email,
                        "ics_url": ics_url,
                        "updated_at": datetime.now()
                    }},
                    upsert=True
                )
                print("ICS URL saved successfully")
            except Exception as e:
                flash(GENERIC_DB_ERROR, 'error')
                logger.error(f"MongoDB error: {e}")
            
        # Always exclude past events by passing False
        result = sync_with_tasklist(session['user'], events, False)
        
        if result['success']:
            return render_template('import_success.html',
                                  tasklist_title=result['tasklist_title'],
                                  task_count=result['task_count'],
                                  updated_count=result.get('updated_count', 0),
                                  is_sync=True)
        else:
            logger.error(f"Sync failed for calendar: {result.get('error')}")
            flash('We could not sync your calendar tasks. Please try again later.', 'error')
            return render_template('import_ics.html', saved_link=ics_url)
            
    except Exception as e:
        logger.error(f"Error in sync_calendar: {e}")
        flash('Something went wrong while processing your calendar. Please try again later.', 'error')
        return render_template('import_ics.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')

@app.route('/delete-link', methods=['POST'])
def delete_link():
    # Check if user is logged in
    if not session.get('user'):
        flash('Please log in to delete your calendar link', 'error')
        return redirect(url_for('home'))
    
    # Get user's email from session
    user_email = session.get('user', {}).get('userinfo', {}).get('email')
    
    if user_email and db is not None:
        try:
            # Delete the ICS URL from the database
            result = db.user_links.delete_one({"email": user_email})
            
            if result.deleted_count > 0:
                flash('Your calendar link has been successfully deleted', 'info')
            else:
                flash('No calendar link found to delete', 'warning')
                
        except Exception as e:
            flash(GENERIC_DB_ERROR, 'error')
            logger.error(f"MongoDB error: {e}")
    
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run()
    # app.run(host="0.0.0.0", port=app_config['FLASK_PORT'], debug=os.getenv("FLASK_ENV") == "development")