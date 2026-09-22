# Calendar to Google Tasks Sync

A web application that allows users to sync their calendar events from Canvas and other educational platforms directly to Google Tasks. This tool helps students and educators manage their assignments, deadlines, and events by automatically converting them from iCal/ICS feeds into manageable tasks.

## Features

- OAuth authentication with Google
- Import calendar events from Canvas and other educational platforms via ICS URLs
- Works with any standard iCal/ICS feed (not just limited to Canvas)
- Automatic syncing of educational assignments and deadlines to Google Tasks
- Background scheduled syncing
- MongoDB storage for user preferences
- Clean, responsive UI

## Use Cases

While primarily designed for Canvas LMS calendar integration, this application can convert any ICS/iCal format calendar link to Google Tasks, including:

- Canvas assignments and deadlines
- Blackboard and other LMS calendars
- University timetables
- Apple Calendar or Outlook exported calendars
- Any calendar that provides an ICS/iCal feed URL

## Requirements

- Python 3.7+
- MongoDB Atlas account (or local MongoDB instance)
- Google Cloud Platform account with OAuth credentials

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd canvas_to_tasks
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
   - Copy the `.env.example` file to `.env`
   - Fill in your credentials

```bash
cp .env.example .env
# Edit .env with your preferred editor
```

4. Set up Google Cloud Platform:
   - Create a project in Google Cloud Console
   - Enable the Google Tasks API
   - Configure the OAuth consent screen
   - Create OAuth 2.0 credentials
   - Add the redirect URI: `http://localhost:3000/auth`

## Usage

### Running the application

```bash
python server.py
```

The application will be available at `http://localhost:3000`

### Using the background sync service

To enable automatic background syncing:

```bash
python background_sync.py
```

This will sync users' calendars with their Google Tasks every hour.

## Configuration

The following environment variables can be configured in `.env`:

- `OAUTH_CLIENT_ID`: Google OAuth client ID
- `OAUTH_CLIENT_SECRET`: Google OAuth client secret
- `FLASK_SECRET`: Secret key for Flask sessions
- `FLASK_PORT`: Port number (default: 3000)
- `FLASK_ENV`: Environment (development/production)
- `MONGO_DB_USER`: MongoDB username
- `MONGO_DB_PASS`: MongoDB password
- `MONGO_DB_NAME`: MongoDB database name

## Project Structure

- `server.py`: Main Flask application
- `util.py`: Utility functions for calendar processing and Google Tasks integration
- `background_sync.py`: Background service for automatic syncing
- `templates/`: HTML templates
- `static/`: CSS and JavaScript files

## License

Copyright (C) 2025 Mehul Patwari

Canvas to Tasks is free software, licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

You're free to use, modify, and share it, including commercially. If you distribute a modified version, or run one as a service that other people use, you must make its complete source code available to them under the same license.
