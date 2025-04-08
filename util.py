import requests
from icalendar import Calendar
from datetime import datetime, date, timezone

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials


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
    
    return events

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
        # Create credentials from OAuth token
        creds = Credentials(
            token=oauth_token.get('access_token'),
            refresh_token=oauth_token.get('refresh_token'),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=oauth_token.get('client_id'),
            client_secret=oauth_token.get('client_secret'),
            scopes=["https://www.googleapis.com/auth/tasks"]
        )

        service = build("tasks", "v1", credentials=creds)

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
                print("end", task['due'], event['end'])
            elif event['start']:
                task['due'] = convert_to_rfc3339(event['start'])
                print("start", task['due'], event['start'])
            
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
            
            service.tasks().insert(tasklist=tasklist_id, body=task).execute()
            task_count += 1

        return {
            "success": True,
            "tasklist_id": tasklist_id,
            "tasklist_title": tasklist_title,
            "task_count": task_count
        }
        
    except HttpError as err:
        return {
            "success": False,
            "error": str(err)
        }
    except Exception as err:
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
        # Create credentials from OAuth token
        creds = Credentials(
            token=oauth_token.get('access_token'),
            refresh_token=oauth_token.get('refresh_token'),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=oauth_token.get('client_id'),
            client_secret=oauth_token.get('client_secret'),
            scopes=["https://www.googleapis.com/auth/tasks"]
        )

        service = build("tasks", "v1", credentials=creds)
        
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
            tasks_result = service.tasks().list(tasklist=dot_tasklist_id).execute()
            existing_tasks = tasks_result.get('items', [])
        
        # Create a set of existing task identifiers (title + due date)
        existing_task_ids = set()
        for task in existing_tasks:
            task_id = f"{task.get('title')}|{convert_to_rfc3339(task.get('due', ''))}"

            existing_task_ids.add(task_id)


        # Add events as tasks to the tasklist if they don't already exist
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
                print(task['title'])
                print("end", task['due'], event['end'])
            elif event['start']:
                print(task['title'])
                task['due'] = convert_to_rfc3339(event['start'])
                print("start", task['due'], event['start'])
            
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

            # Check if this task already exists
            task_id = f"{task['title']}|{task.get('due', '')}"
            # print("task_id", task_id)
            # print("existing_task_ids", existing_task_ids)
            if task_id not in existing_task_ids:
  
                service.tasks().insert(tasklist=dot_tasklist_id, body=task).execute()
                existing_task_ids.add(task_id)  # Add to set to prevent duplicates within this batch
                task_count += 1

        return {
            "success": True,
            "tasklist_id": dot_tasklist_id,
            "tasklist_title": 'dot_tasklist',
            "task_count": task_count,
            "is_sync": True
        }
        
    except HttpError as err:
        return {
            "success": False,
            "error": str(err)
        }
    except Exception as err:
        return {
            "success": False,
            "error": str(err)
        }