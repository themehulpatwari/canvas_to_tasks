import requests
from icalendar import Calendar
from datetime import datetime, date, timezone
import logging
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google.auth.exceptions import RefreshError

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def refresh_oauth_token(oauth_token):
    """
    Attempts to refresh an expired OAuth token.
    
    Args:
        oauth_token (dict): The expired OAuth token information
        
    Returns:
        dict: The refreshed token information or None if refresh failed
    """
    try:
        refresh_token = oauth_token.get('refresh_token')
        if not refresh_token:
            logging.error("No refresh token available")
            return None
            
        client_id = oauth_token.get('client_id')
        client_secret = oauth_token.get('client_secret')
        
        # Make a refresh token request
        refresh_url = "https://oauth2.googleapis.com/token"
        payload = {
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
        
        response = requests.post(refresh_url, data=payload)
        
        if response.status_code == 200:
            new_token_data = response.json()
            # Update the token information while keeping the refresh token
            oauth_token.update({
                'access_token': new_token_data.get('access_token'),
                'expires_in': new_token_data.get('expires_in'),
                'token_type': new_token_data.get('token_type')
            })
            logging.info("OAuth token refreshed successfully")
            return oauth_token
        else:
            logging.error(f"Failed to refresh token: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logging.error(f"Error refreshing OAuth token: {str(e)}")
        return None

def get_tasks_service(oauth_token):
    """
    Creates and returns an authenticated Google Tasks API service.
    Handles token refresh if the current token is invalid.
    
    Args:
        oauth_token (dict): OAuth token from Google authentication
        
    Returns:
        tuple: (service object, updated oauth_token)
    """
    try:
        # Create credentials from OAuth token
        creds = Credentials(
            token=oauth_token.get('access_token'),
            refresh_token=oauth_token.get('refresh_token'),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=oauth_token.get('client_id'),
            client_secret=oauth_token.get('client_secret'),
            scopes=["https://www.googleapis.com/auth/tasks"]
        )
        
        # Build the service
        service = build("tasks", "v1", credentials=creds)
        
        # Make a simple API call to verify the token is valid
        service.tasklists().list(maxResults=1).execute()
        
        # If we get here, the token is valid
        return service, oauth_token
        
    except HttpError as err:
        if err.resp.status in [401, 403]:
            logging.info("Authentication error. Attempting to refresh token...")
            refreshed_token = refresh_oauth_token(oauth_token)
            
            if refreshed_token:
                # Try again with the refreshed token
                try:
                    creds = Credentials(
                        token=refreshed_token.get('access_token'),
                        refresh_token=refreshed_token.get('refresh_token'),
                        token_uri="https://oauth2.googleapis.com/token",
                        client_id=refreshed_token.get('client_id'),
                        client_secret=refreshed_token.get('client_secret'),
                        scopes=["https://www.googleapis.com/auth/tasks"]
                    )
                    service = build("tasks", "v1", credentials=creds)
                    service.tasklists().list(maxResults=1).execute()
                    return service, refreshed_token
                except Exception as e:
                    logging.error(f"Still failed after token refresh: {str(e)}")
                    raise
            else:
                logging.error("Token refresh failed")
                raise
        else:
            logging.error(f"HTTP Error: {str(err)}")
            raise
    except Exception as err:
        logging.error(f"Error creating Google Tasks service: {str(err)}")
        raise

def convert_to_rfc3339(event_start):
    """
    Converts event_start (which can be a datetime.date or datetime.datetime)
    to an RFC3339 formatted string.
    Always sets time to 00:00:00 as Google Tasks only uses the date part.

    """
    
    if isinstance(event_start, datetime):
        # Ensure the datetime is timezone aware; if not, assume UTC
        # Reset time to midnight but keep the timezone
        midnight = event_start.replace(hour=0, minute=0, second=0, microsecond=0)
        if midnight.tzinfo is None:
            midnight = midnight.replace(tzinfo=timezone.utc)
        return midnight.isoformat()


    elif isinstance(event_start, date):
        # Convert date to datetime at midnight UTC
        event_datetime = datetime.combine(event_start, datetime.min.time(), timezone.utc)
        return event_datetime.isoformat()
    elif isinstance(event_start, str):
        # Handle string inputs in ISO 8601 format
        try:
            # Replace 'Z' with '+00:00' for UTC timezone as fromisoformat doesn't handle 'Z'
            if event_start.endswith('Z'):
                event_start = event_start[:-1] + '+00:00'
            # Parse the string to datetime
            event_datetime = datetime.fromisoformat(event_start)
            # Reset time to midnight but keep the timezone
            event_datetime = event_datetime.replace(hour=0, minute=0, second=0, microsecond=0)

            # Ensure timezone is set
            if event_datetime.tzinfo is None:
                event_datetime = event_datetime.replace(tzinfo=timezone.utc)
            return event_datetime.isoformat()
        except ValueError:
            # If the string format is not valid
            return event_start
    else:
        return ''

def get_ics_events(ics_url: str) -> list[dict]:
    """
    Fetches and parses events from an ICS (iCalendar) file located at the given URL.
    Args:
        ics_url (str): The URL of the ICS file to fetch.
    Returns:
        dict: A dictionary containing the parsed events.
    """

    # Fetch the .ics file from the given URL
    response = requests.get(ics_url)
    
    if response.status_code != 200:
        raise Exception(f"Failed to fetch the ics file. Status code: {response.status_code}")
    
    # Parse the ICS content
    cal = Calendar.from_ical(response.content)
    
    events = []
    
    for component in cal.walk():
        if component.name == "VEVENT":
            event = {
                "summary": str(component.get('summary')) if component.get('summary') else None,
                "start": component.get('dtstart').dt if component.get('dtstart') else None,
                "end": component.get('dtend').dt if component.get('dtend') else None,
                "location": str(component.get('location')) if component.get('location') else None,
                "description": str(component.get('description')) if component.get('description') else None
            }
                
            events.append(event)
    
    logging.debug(f"Parsed {len(events)} events from ICS file")
    return events

def validate_task(task):
    """
    Validates and sanitizes a task for Google Tasks API requirements.
    
    Args:
        task (dict): The task to validate
        
    Returns:
        dict: The sanitized task or None if task is invalid
    """
    # Make a copy to avoid modifying the original
    sanitized = task.copy()
    
    # Validate title - Google Tasks requires non-empty title
    if not sanitized.get('title') or len(sanitized.get('title', '').strip()) == 0:
        sanitized['title'] = 'Untitled Task'
    
    # Limit title length (Google has undocumented limits)
    if len(sanitized.get('title', '')) > 500:
        sanitized['title'] = sanitized['title'][:497] + '...'
    
    # Validate notes
    if sanitized.get('notes') and len(sanitized['notes']) > 8000:  # Google Tasks has undocumented note length limits
        sanitized['notes'] = sanitized['notes'][:7997] + '...'
    
    # Validate due date format
    if 'due' in sanitized:
        # Ensure it's a valid RFC3339 timestamp
        try:
            # Test if it's valid by parsing it
            datetime.fromisoformat(sanitized['due'].replace('Z', '+00:00'))
        except (ValueError, TypeError, AttributeError):
            # If invalid, remove it
            logging.warning(f"Invalid due date removed from task: {sanitized.get('title')}")
            del sanitized['due']
    
    return sanitized

def insert_into_tasklist(oauth_token, events, include_past_events=True):
    """
    Inserts a list of events into a new Google Tasks tasklist using OAuth token.
    Args:
        oauth_token (dict): OAuth token from Google authentication
        events (list): A list of event dictionaries
        include_past_events (bool): Whether to include events with end dates in the past
    Returns:
        dict: Information about the created tasklist and task count
    """
    try:
        # Get an authenticated service with token refresh handling
        service, updated_token = get_tasks_service(oauth_token)

        # Create a new tasklist with current timestamp
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
        tasklist = {
            'title': f'dot_tasklist'
        }
        result = service.tasklists().insert(body=tasklist).execute()
        tasklist_id = result['id']
        tasklist_title = result['title']

        # Add events as tasks to the new tasklist
        task_count = 0
        current_date = datetime.now(timezone.utc).date()
        
        for event in events:
            # Create the task structure first
            task = {
                'title': event['summary'] if event['summary'] is not None else 'Untitled Event',
                'notes': event['description'] if event['description'] is not None else '',
                'status': 'needsAction'
            }
            
            # Set the due date
            if event['end']:
                task['due'] = convert_to_rfc3339(event['end'])
                logging.debug(f"end {task['due']} {event['end']}")
            elif event['start']:
                task['due'] = convert_to_rfc3339(event['start'])
                logging.debug(f"start {task['due']} {event['start']}")
            
            # Skip events that have already ended if include_past_events is False
            if not include_past_events and 'due' in task:
                # Parse the RFC3339 date to compare with current date
                due_str = task['due']
                try:
                    due_date = datetime.fromisoformat(due_str.replace('Z', '+00:00')).date()
                    if due_date < current_date:
                        continue
                except (ValueError, TypeError):
                    # If there's an error parsing the date, include the event
                    pass
            
            # Validate and sanitize the task
            validated_task = validate_task(task)
            
            # Insert the task with error handling
            try:
                service.tasks().insert(tasklist=tasklist_id, body=validated_task).execute()
                task_count += 1
                logging.info(f"Added task: {validated_task['title']} due: {validated_task.get('due')}")
            except HttpError as insert_err:
                logging.error(f"Failed to insert task '{validated_task['title']}': {str(insert_err)}")
                # Log additional details for debugging
                logging.debug(f"Task data: {validated_task}")

        return {
            "success": True,
            "tasklist_id": tasklist_id,
            "tasklist_title": tasklist_title,
            "task_count": task_count,
            "oauth_token": updated_token  # Return the possibly refreshed token
        }
        
    except HttpError as err:
        logging.error(f"HTTP Error in insert_into_tasklist: {str(err)}")
        return {
            "success": False,
            "error": str(err)
        }
    except Exception as err:
        logging.error(f"Error in insert_into_tasklist: {str(err)}")
        return {
            "success": False,
            "error": str(err)
        }

def sync_with_tasklist(oauth_token, events, include_past_events=True):
    """
    Syncs events with an existing 'dot_tasklist' in Google Tasks.
    Adds only events that don't already exist in the tasklist.
    
    Args:
        oauth_token (dict): OAuth token from Google authentication
        events (list): A list of event dictionaries
        include_past_events (bool): Whether to include events with end dates in the past
    
    Returns:
        dict: Information about the sync operation including new task count
    """
    try:
        # Get an authenticated service with token refresh handling
        service, updated_token = get_tasks_service(oauth_token)
        
        # Find the dot_tasklist
        tasklists = service.tasklists().list().execute()
        dot_tasklist_id = None
        for tasklist in tasklists.get('items', []):
            if tasklist['title'] == 'dot_tasklist':
                dot_tasklist_id = tasklist['id']
                break
        
        # If dot_tasklist doesn't exist, create it
        if not dot_tasklist_id:
            tasklist = {'title': 'dot_tasklist'}
            result = service.tasklists().insert(body=tasklist).execute()
            dot_tasklist_id = result['id']
            existing_tasks = []
        else:
            # Get all existing tasks from the dot_tasklist
            # Make sure to get ALL tasks including completed and hidden ones
            existing_tasks = []
            page_token = None
            
            while True:
                tasks_result = service.tasks().list(
                    tasklist=dot_tasklist_id,
                    showCompleted=True,
                    showHidden=True,
                    maxResults=100,
                    pageToken=page_token
                ).execute()
                
                existing_tasks.extend(tasks_result.get('items', []))
                
                page_token = tasks_result.get('nextPageToken')
                if not page_token:
                    break
        
        # Create a set of existing task titles (normalized)
        existing_task_titles = set()
        for task in existing_tasks:
            if task.get('title'):
                # Normalize the title by trimming whitespace and converting to lowercase
                normalized_title = task.get('title', '').strip().lower()
                existing_task_titles.add(normalized_title)

        # Add events as tasks to the tasklist if they don't already exist
        task_count = 0
        error_count = 0
        current_date = datetime.now(timezone.utc).date()
        
        for event in events:
            try:
                # Create the task structure first
                task = {
                    'title': event['summary'] if event['summary'] is not None else 'Untitled Event',
                    'notes': event['description'] if event['description'] is not None else '',
                    'status': 'needsAction'
                }
                
                # Set the due date
                if event['end']:
                    task['due'] = convert_to_rfc3339(event['end'])
                    logging.debug(f"end {task['due']} {event['end']}")
                elif event['start']:
                    task['due'] = convert_to_rfc3339(event['start'])
                    logging.debug(f"start {task['due']} {event['start']}")
                
                # Skip events that have already ended if include_past_events is False
                if not include_past_events and 'due' in task:
                    # Parse the RFC3339 date to compare with current date
                    due_str = task['due']
                    try:
                        due_date = datetime.fromisoformat(due_str.replace('Z', '+00:00')).date()
                        if due_date < current_date:
                            continue
                    except (ValueError, TypeError):
                        # If there's an error parsing the date, include the event
                        pass

                # Check if this task already exists using normalized title only
                normalized_title = task['title'].strip().lower()
                
                # Check only by task name, ignoring date
                if normalized_title not in existing_task_titles:
                    
                    # Validate and sanitize the task
                    validated_task = validate_task(task)
                    
                    # Insert the task with error handling
                    try:
                        service.tasks().insert(tasklist=dot_tasklist_id, body=validated_task).execute()
                        existing_task_titles.add(normalized_title)  # Add to set to prevent duplicates within this batch
                        task_count += 1
                        logging.info(f"Added task: {validated_task['title']} due: {validated_task.get('due')}")
                    except HttpError as insert_err:
                        error_count += 1
                        logging.error(f"Failed to insert task '{validated_task['title']}': {str(insert_err)}")
                        # Log additional details for debugging
                        logging.debug(f"Task data: {validated_task}")
                else:
                    logging.info(f"Skipped duplicate task: {task['title']}")
            except Exception as task_err:
                error_count += 1
                logging.error(f"Error processing event: {str(task_err)}")

        result = {
            "success": True,
            "tasklist_id": dot_tasklist_id,
            "tasklist_title": 'dot_tasklist',
            "task_count": task_count,
            "error_count": error_count,
            "is_sync": True,
            "oauth_token": updated_token  # Return the possibly refreshed token
        }
        
        # If we had errors but some tasks were successful, still return success
        if error_count > 0 and task_count > 0:
            result["partial_success"] = True
            result["message"] = f"Added {task_count} tasks with {error_count} errors"
            
        return result
        
    except HttpError as err:
        logging.error(f"HTTP Error in sync_with_tasklist: {str(err)}")
        return {
            "success": False,
            "error": str(err),
        }
    except Exception as err:
        logging.error(f"Error in sync_with_tasklist: {str(err)}")
        return {
            "success": False,
            "error": str(err),
        }