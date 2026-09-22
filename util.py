import os
import re
import socket
import ipaddress
import requests
from urllib.parse import urljoin, urlparse
from icalendar import Calendar
from datetime import datetime, date, time as dt_time, timedelta, timezone
from zoneinfo import ZoneInfo
import logging
from cryptography.fernet import Fernet, InvalidToken
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google.auth.exceptions import RefreshError

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Outbound request safety limits ---
HTTP_TIMEOUT = 15              # seconds, applied to all outbound calls
ICS_MAX_BYTES = 10 * 1024 * 1024   # cap ICS download at 10 MB
ICS_MAX_REDIRECTS = 5
TZ_TIMEOUT = 5                 # keep the timezone lookup off the critical path
TZ_MAX_BYTES = 512 * 1024      # the ENV blob sits near the top of the page

# How far back to shift a due time when we can't determine the real timezone.
# Google Tasks keeps only the date part of 'due', so a Canvas deadline that
# Canvas publishes as a UTC instant (8pm Wednesday Eastern -> 2026-09-24T00:00Z)
# otherwise reads as Thursday. 10 hours is the offset of the westernmost US
# timezone, so shifting by it never lands a task *after* its real day; the
# worst case is a deadline set between midnight and dawn showing a day early,
# which is the safe direction to be wrong in.
FALLBACK_SHIFT_HOURS = 10


class UnsafeURLError(Exception):
    """Raised when an ICS URL targets a non-public / disallowed destination."""


def _is_public_ip(addr):
    """True only for globally-routable addresses (blocks private/loopback/etc.)."""
    ip = ipaddress.ip_address(addr)
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _validate_public_url(url):
    """
    SSRF guard: only allow http(s) URLs whose host resolves *entirely* to
    public IP addresses. Blocks localhost, private ranges, and cloud metadata
    endpoints (e.g. 169.254.169.254, which is link-local).

    Note: this resolves DNS and checks every returned address; there is a
    residual DNS-rebinding window between this check and the actual connection,
    which is an accepted trade-off for this app.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise UnsafeURLError(f"Unsupported URL scheme: {parsed.scheme or '(none)'}")
    host = parsed.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UnsafeURLError(f"Could not resolve host: {host}") from e
    addrs = {info[4][0] for info in infos}
    if not addrs:
        raise UnsafeURLError(f"Host did not resolve: {host}")
    for addr in addrs:
        if not _is_public_ip(addr):
            raise UnsafeURLError(f"Host resolves to a non-public address: {addr}")


def _fetch_ics(url):
    """
    Fetch an ICS feed safely: SSRF-validate the URL (and every redirect hop),
    enforce a timeout, and cap the downloaded size. Returns raw bytes.
    """
    current = url
    for _ in range(ICS_MAX_REDIRECTS + 1):
        _validate_public_url(current)
        resp = requests.get(
            current, timeout=HTTP_TIMEOUT, allow_redirects=False, stream=True
        )
        try:
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get('Location')
                if not location:
                    raise Exception("Redirect response missing Location header")
                current = urljoin(current, location)
                continue
            if resp.status_code != 200:
                raise Exception(
                    f"Failed to fetch the ics file. Status code: {resp.status_code}"
                )
            chunks = []
            total = 0
            for chunk in resp.iter_content(8192):
                total += len(chunk)
                if total > ICS_MAX_BYTES:
                    raise Exception("ICS file exceeds the maximum allowed size")
                chunks.append(chunk)
            return b''.join(chunks)
        finally:
            resp.close()
    raise Exception("Too many redirects while fetching the ICS file")

def _get_fernet():
    """
    Returns a Fernet built from TOKEN_ENC_KEY, or None if the key is unset or
    invalid. When None, token encryption is a no-op so the app keeps working
    until the key is provisioned (refresh tokens stay plaintext, as before).
    """
    key = os.getenv("TOKEN_ENC_KEY")
    if not key:
        return None
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        logging.error("TOKEN_ENC_KEY is set but invalid; refresh tokens will not be encrypted")
        return None


def encrypt_token(plaintext):
    """Encrypts a refresh token for storage. No-op if no key is configured."""
    if plaintext is None:
        return None
    fernet = _get_fernet()
    if fernet is None:
        return plaintext
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_token(value):
    """
    Decrypts a stored refresh token. Transparently passes through values that
    were stored as plaintext before encryption was enabled (legacy rows), so
    migration is seamless.
    """
    if value is None:
        return None
    fernet = _get_fernet()
    if fernet is None:
        return value
    try:
        return fernet.decrypt(value.encode()).decode()
    except InvalidToken:
        return value  # legacy plaintext value


def revoke_google_token(token):
    """
    Revokes a Google OAuth grant. Revoking the refresh token invalidates the
    whole authorization. Best-effort: returns True on success, False otherwise.
    """
    if not token:
        return False
    try:
        resp = requests.post(
            "https://oauth2.googleapis.com/revoke",
            params={'token': token},
            headers={'content-type': 'application/x-www-form-urlencoded'},
            timeout=HTTP_TIMEOUT,
        )
        return resp.status_code == 200
    except Exception as e:
        logging.error(f"Failed to revoke Google token: {e}")
        return False


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
        
        response = requests.post(refresh_url, data=payload, timeout=HTTP_TIMEOUT)
        
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

# Canvas embeds the institution's configured timezone in the ENV blob on its
# login page, e.g. "TIMEZONE":"America/New_York".
_TZ_RE = re.compile(r'"TIMEZONE":"([\w/+\-]{3,64})"')

# Resolved timezones, keyed by host. One lookup per Canvas instance per process
# instead of one per user.
_tz_cache = {}


def canvas_timezone(ics_url):
    """
    Returns the IANA timezone of the Canvas instance serving this feed, or
    None if it can't be determined.

    Assignment due times are set in the institution's timezone, so that is what
    decides which calendar day a due instant belongs to. The feed itself carries
    no timezone at all -- no X-WR-TIMEZONE, no VTIMEZONE, no TZID -- so we read
    it off the same host's login page instead.
    """
    host = urlparse(ics_url).hostname if ics_url else None
    if not host:
        return None
    if host in _tz_cache:
        return _tz_cache[host]

    name = None
    url = f'https://{host}/login/canvas'
    try:
        _validate_public_url(url)  # same SSRF guard the feed fetch uses
        resp = requests.get(url, timeout=TZ_TIMEOUT, stream=True)
        try:
            chunks, total = [], 0
            for chunk in resp.iter_content(8192):
                chunks.append(chunk)
                total += len(chunk)
                if total >= TZ_MAX_BYTES:
                    break
        finally:
            resp.close()
        # Parsed regardless of status code: some hosts answer 404 with a page
        # that still carries the blob.
        match = _TZ_RE.search(b''.join(chunks).decode('utf-8', 'replace'))
        if match:
            ZoneInfo(match.group(1))  # reject anything that isn't a real zone
            name = match.group(1)
    except Exception as e:
        logging.info(f"No timezone available from {host}: {type(e).__name__}")

    _tz_cache[host] = name
    return name


def is_timed(value):
    """True for a due value that carries a real time (and so needs a timezone)."""
    return isinstance(value, datetime) and value.tzinfo is not None


def convert_to_rfc3339(event_start, tz=None):
    """
    Converts a due value (datetime.date, datetime.datetime, or ISO 8601 string)
    to the RFC3339 string Google Tasks wants for 'due'.

    Google Tasks keeps only the date part of this field, so the result is always
    midnight UTC on the intended day and the whole job is picking that day.
    All-day events already name one. Timed events arrive as UTC instants, which
    is where the day can slip: convert into `tz` when we know it, otherwise fall
    back to shifting (see FALLBACK_SHIFT_HOURS).
    """
    if isinstance(event_start, datetime):
        local_date = _local_date(event_start, tz)
    elif isinstance(event_start, date):
        local_date = event_start  # all-day; already the right calendar day
    elif isinstance(event_start, str):
        try:
            # fromisoformat doesn't accept a trailing 'Z' on older versions.
            text = event_start[:-1] + '+00:00' if event_start.endswith('Z') else event_start
            local_date = _local_date(datetime.fromisoformat(text), tz)
        except ValueError:
            return event_start  # not a format we understand; hand it back
    else:
        return ''

    return datetime.combine(local_date, dt_time.min, timezone.utc).isoformat()


def _local_date(value, tz):
    """The calendar day a datetime belongs to, from the reader's point of view."""
    if value.tzinfo is None:
        return value.date()  # naive: the wall clock is already local
    if tz is not None:
        return value.astimezone(tz).date()
    return (value - timedelta(hours=FALLBACK_SHIFT_HOURS)).date()


def get_ics_events(ics_url: str) -> list[dict]:
    """
    Fetches and parses events from an ICS (iCalendar) file located at the given URL.
    Args:
        ics_url (str): The URL of the ICS file to fetch.
    Returns:
        dict: A dictionary containing the parsed events.
    """

    # Fetch the .ics file safely (SSRF-validated, timed out, size-capped)
    content = _fetch_ics(ics_url)

    # Parse the ICS content
    cal = Calendar.from_ical(content)
    
    events = []
    
    for component in cal.walk():
        if component.name == "VEVENT":
            event = {
                "summary": str(component.get('summary')) if component.get('summary') else None,
                "start": component.get('dtstart').dt if component.get('dtstart') else None,
                "end": component.get('dtend').dt if component.get('dtend') else None,
                "location": str(component.get('location')) if component.get('location') else None,
                "description": str(component.get('description')) if component.get('description') else None,
                # Stable identity for upsert matching. Canvas emits a UID like
                # "event-assignment-1813708" that does NOT change when the due
                # date moves, so it is the correct dedup key. recurrence_id
                # distinguishes individually-edited instances of a series.
                "uid": str(component.get('uid')) if component.get('uid') else None,
                "recurrence_id": str(component.get('recurrence-id')) if component.get('recurrence-id') else None,
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

# Notes field length cap (Google Tasks has an undocumented limit ~8000 chars).
NOTES_LIMIT = 8000

# Marker we embed in a task's notes to carry the source event's stable id.
# Google Tasks has no custom-metadata field, so this is how a synced task
# identifies itself on the next run. Example: [ctt-uid:event-assignment-1813708]
_UID_MARKER_RE = re.compile(r'\[ctt-uid:([^\]]+)\]')


def event_key(event):
    """
    Builds the stable identity for an event: its ICS UID, plus the
    recurrence-id when the event is a modified instance of a series.
    Returns None when the feed provides no UID (caller falls back to title).
    """
    uid = event.get('uid')
    if not uid:
        return None
    rid = event.get('recurrence_id')
    return f'{uid}::{rid}' if rid else uid


def extract_uid(notes):
    """Returns the embedded ctt-uid marker value from a task's notes, or None."""
    if not notes:
        return None
    match = _UID_MARKER_RE.search(notes)
    return match.group(1) if match else None


def with_uid_marker(text, key):
    """
    Appends the [ctt-uid:<key>] marker to notes text, truncating the body if
    needed so the whole thing (marker included) stays within NOTES_LIMIT and
    the marker is never the part that gets cut off. No-op if the text already
    carries a marker or there is no key.
    """
    text = text or ''
    if not key or extract_uid(text):
        return text
    marker = f'[ctt-uid:{key}]'
    sep = '\n\n' if text else ''
    budget = NOTES_LIMIT - len(marker) - len(sep)
    if len(text) > budget:
        text = text[:max(0, budget - 3)] + '...'
        sep = '\n\n'
    return f'{text}{sep}{marker}'


def _due_date_part(due_str):
    """Parses an RFC3339 'due' string down to a date for comparison, or None."""
    if not due_str:
        return None
    try:
        return datetime.fromisoformat(due_str.replace('Z', '+00:00')).date()
    except (ValueError, TypeError, AttributeError):
        return None


def _match_title(title):
    """
    Normalizes a title to the form a previously-inserted task would have been
    stored under, so legacy (pre-UID) tasks adopt by title instead of being
    duplicated. Mirrors the >500-char truncation validate_task applies before
    insert, then trims/lowercases. Keeping this in sync with validate_task is
    what makes the first-run migration line up for long titles.
    """
    title = title or ''
    if len(title) > 500:
        title = title[:497] + '...'
    return title.strip().lower()


def sync_with_tasklist(oauth_token, events, include_past_events=True, ics_url=None):
    """
    Upserts events into the 'dot_tasklist' in Google Tasks.

    Each task is matched to its source event by the stable ICS UID embedded in
    the task's notes (see with_uid_marker). On a match, the due date / title are
    patched if they changed in Canvas (e.g. an assignment was rescheduled). With
    no match, the event is inserted as a new task. Tasks created before UID
    embedding existed are adopted on a one-time normalized-title match and then
    tagged, so existing users don't get everything duplicated.

    Args:
        oauth_token (dict): OAuth token from Google authentication
        events (list): A list of event dictionaries
        include_past_events (bool): Whether to insert events whose due date is in
            the past. Updates to already-tracked tasks happen regardless, so a
            date that slips into the past is still corrected.
        ics_url (str): The feed's URL, used to look up the institution's
            timezone when the feed contains timed events. Optional; without it
            those events fall back to the shift (see convert_to_rfc3339).

    Returns:
        dict: Counts of added / updated / skipped tasks for the sync operation.
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

        # Index existing tasks two ways: by embedded UID (the real key) and by
        # normalized title (legacy fallback to adopt pre-UID tasks once).
        by_uid = {}
        by_title = {}
        for task in existing_tasks:
            uid = extract_uid(task.get('notes'))
            if uid:
                by_uid[uid] = task
            if task.get('title'):
                by_title.setdefault(_match_title(task['title']), task)

        added_count = 0
        updated_count = 0
        skipped_count = 0
        error_count = 0
        current_date = datetime.now(timezone.utc).date()

        # Only feeds with timed events need a timezone, so a feed of nothing but
        # all-day assignments never triggers the lookup.
        tz = None
        if any(is_timed(e['end'] or e['start']) for e in events):
            tz_name = canvas_timezone(ics_url)
            tz = ZoneInfo(tz_name) if tz_name else None
            logging.info(f"Timed events present; using timezone {tz_name or 'fallback shift'}")

        for event in events:
            try:
                key = event_key(event)
                title = event['summary'] if event['summary'] is not None else 'Untitled Event'
                description = event['description'] if event['description'] is not None else ''

                # Desired due date (Canvas assignments only carry a start date)
                due = None
                if event['end']:
                    due = convert_to_rfc3339(event['end'], tz)
                elif event['start']:
                    due = convert_to_rfc3339(event['start'], tz)

                # Locate an existing task: prefer the UID match, otherwise adopt
                # a legacy task that matches by title and has no marker yet.
                existing = None
                adopt_legacy = False
                if key and key in by_uid:
                    existing = by_uid[key]
                else:
                    candidate = by_title.get(_match_title(title))
                    if candidate is not None and extract_uid(candidate.get('notes')) is None:
                        existing = candidate
                        adopt_legacy = True

                if existing is not None:
                    # UPDATE path — always allowed, even if the due date moved
                    # into the past (correcting exactly that is the point).
                    patch = {}
                    if existing.get('title') != title:
                        patch['title'] = title
                    if due and _due_date_part(existing.get('due')) != _due_date_part(due):
                        patch['due'] = due
                    if adopt_legacy and key:
                        # Tag the legacy task so future syncs match it by UID.
                        patch['notes'] = with_uid_marker(existing.get('notes'), key)

                    if patch:
                        try:
                            service.tasks().patch(
                                tasklist=dot_tasklist_id, task=existing['id'], body=patch
                            ).execute()
                            existing.update(patch)
                            updated_count += 1
                            logging.info(f"Updated task: {title} due: {existing.get('due')}")
                        except HttpError as patch_err:
                            error_count += 1
                            logging.error(f"Failed to update task '{title}': {str(patch_err)}")
                    else:
                        skipped_count += 1
                        logging.info(f"No change for task: {title}")

                    if key:
                        by_uid[key] = existing
                    continue

                # INSERT path — only here do we honor include_past_events.
                if not include_past_events and due:
                    d = _due_date_part(due)
                    if d is not None and d < current_date:
                        skipped_count += 1
                        continue

                task = {
                    'title': title,
                    'notes': with_uid_marker(description, key),
                    'status': 'needsAction'
                }
                if due:
                    task['due'] = due

                validated_task = validate_task(task)
                try:
                    created = service.tasks().insert(
                        tasklist=dot_tasklist_id, body=validated_task
                    ).execute()
                    if key:
                        by_uid[key] = created
                    by_title.setdefault(_match_title(title), created)
                    added_count += 1
                    logging.info(f"Added task: {validated_task['title']} due: {validated_task.get('due')}")
                except HttpError as insert_err:
                    error_count += 1
                    logging.error(f"Failed to insert task '{validated_task['title']}': {str(insert_err)}")
                    logging.debug(f"Task data: {validated_task}")
            except Exception as task_err:
                error_count += 1
                logging.error(f"Error processing event: {str(task_err)}")

        result = {
            "success": True,
            "tasklist_id": dot_tasklist_id,
            "tasklist_title": 'dot_tasklist',
            "task_count": added_count,
            "updated_count": updated_count,
            "skipped_count": skipped_count,
            "error_count": error_count,
            "is_sync": True,
            "oauth_token": updated_token  # Return the possibly refreshed token
        }

        # If we had errors but some tasks were successful, still return success
        if error_count > 0 and (added_count > 0 or updated_count > 0):
            result["partial_success"] = True
            result["message"] = f"Added {added_count}, updated {updated_count}, with {error_count} errors"

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