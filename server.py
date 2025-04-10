from flask import Flask, redirect, render_template, session, url_for, request, flash
from authlib.integrations.flask_client import OAuth
import json
from util import get_ics_events, sync_with_tasklist
from datetime import datetime
import os
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

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
app.config['SESSION_COOKIE_NAME'] = 'my_session'

# MongoDB connection setup
mongo_client = None
db = None

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

oauth = OAuth(app)

oauth.register(
    name='google',
    client_id=app_config['OAUTH_CLIENT_ID'],
    client_secret=app_config['OAUTH_CLIENT_SECRET'],
    server_metadata_url=app_config['OAUTH_META_URL'],
    client_kwargs={
        'scope': ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/tasks'],
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
                flash(f"Database error: {str(e)}", 'error')
                print(f"MongoDB error: {str(e)}")
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
                "client_id": app_config['OAUTH_CLIENT_ID'],
                "client_secret": app_config['OAUTH_CLIENT_SECRET'],
                "last_updated": datetime.now()
            }
            
            # Only include refresh_token in the update if it's present
            if token.get('refresh_token'):
                update_data["refresh_token"] = token.get('refresh_token')
            
            # Store OAuth token information in the database
            db.user_auth.update_one(
                {"email": user_email},
                {"$set": update_data},
                upsert=True
            )

            print(f"OAuth tokens saved for {user_email}")
        except Exception as e:
            print(f"Error saving OAuth tokens: {str(e)}")
    
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
            flash(f"Database error: {str(e)}", 'error')
            print(f"MongoDB error: {str(e)}")
    else:
        flash('No saved calendar link found. Please enter a new ICS URL.', 'info')
    
    # Only pass saved_link to template if it's not None
    template_vars = {}
    if saved_link:
        template_vars['saved_link'] = saved_link
        
    return render_template('import_ics.html', **template_vars)

@app.route('/sync_calendar', methods=['POST'])
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
                flash(f"Database error: {str(e)}", 'error')
                print(f"MongoDB error: {str(e)}")
            
        # Always exclude past events by passing False
        result = sync_with_tasklist(session['user'], events, False)
        
        if result['success']:
            return render_template('import_success.html', 
                                  tasklist_title=result['tasklist_title'], 
                                  task_count=result['task_count'],
                                  is_sync=True)
        else:
            flash(f'Error syncing Canvas tasks: {result["error"]}', 'error')
            return render_template('import_ics.html', saved_link=ics_url)
            
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return render_template('import_ics.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('terms_of_service.html')

if __name__ == '__main__':
    app.run()
    # app.run(host="0.0.0.0", port=app_config['FLASK_PORT'], debug=os.getenv("FLASK_ENV") == "development")