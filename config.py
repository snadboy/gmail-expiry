"""
Configuration settings for Gmail Expiry application.
"""
from typing import List
import os
from dotenv import load_dotenv
import re

# Load environment variables
load_dotenv()

# OAuth2 Configuration
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
TOKEN_FILE = 'token.pickle'

# API Scopes
SCOPES: List[str] = [
    'https://www.googleapis.com/auth/contacts.readonly',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.labels',
    'https://www.googleapis.com/auth/gmail.modify'
]

# OAuth2 Configuration
OAUTH2_CONFIG = {
    "installed": {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["http://localhost", "urn:ietf:wg:oauth:2.0:oob"]
    }
}

# Label Configuration
KEEP_LABEL_PATTERN = r'^KEEP(_\d+[DWMY])?$'
KEEP_DURATION_PATTERN = re.compile(r'^KEEP_(\d+)([DWMY])$')

# API Batch Configurations
GMAIL_BATCH_SIZE = 100
GMAIL_BATCH_DELAY = 1  # seconds
PEOPLE_BATCH_SIZE = 50
PEOPLE_MAX_MEMBERS = 1000
PEOPLE_PAGE_SIZE = 1000

# Logging Configuration
LOG_FILE = 'gmail_labels.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
LOG_MAX_BYTES = 250000  # approximately 2500 lines at 100 bytes per line
LOG_BACKUP_COUNT = 5

# Time Units (for label duration calculations)
TIME_UNITS = {
    'D': 'days',
    'W': 'weeks',
    'M': 'months',
    'Y': 'years'
}

# Error Handling
MAX_RETRY_ATTEMPTS = 5
MAX_BACKOFF_TIME = 300  # seconds
