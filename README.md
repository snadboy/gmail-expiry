# Google Contacts Labels (Python Version)

This Python script fetches Google Contacts that have labels starting with "KEEP".

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Copy `.env.template` to `.env` and add your Google OAuth2 credentials:
```bash
CLIENT_ID=your_client_id_here
CLIENT_SECRET=your_client_secret_here
```

3. Run the script:
```bash
python main.py
```

## How it works

The script will:
1. Generate an authorization URL for Google OAuth2
2. Ask you to visit the URL and authorize the application
3. Prompt you to enter the authorization code
4. Fetch all contacts that have labels starting with "KEEP"
5. Display the email addresses of contacts grouped by their KEEP labels
