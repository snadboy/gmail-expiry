from dataclasses import dataclass
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import os
import json
import re
import pickle
from typing import Any, Dict, List, Set, Optional, Iterator
import time
import logging
import traceback
from datetime import datetime, date
from collections import defaultdict
from dateutil.relativedelta import relativedelta
from logging.handlers import RotatingFileHandler

from config import (
    SCOPES, OAUTH2_CONFIG, TOKEN_FILE,
    KEEP_LABEL_PATTERN, KEEP_DURATION_PATTERN,
    GMAIL_BATCH_SIZE, GMAIL_BATCH_DELAY,
    PEOPLE_BATCH_SIZE, PEOPLE_MAX_MEMBERS, PEOPLE_PAGE_SIZE,
    LOG_FILE, LOG_FORMAT, LOG_DATE_FORMAT, LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    TIME_UNITS, MAX_RETRY_ATTEMPTS, MAX_BACKOFF_TIME
)

@dataclass
class Metadata:
    update_time: str

    @staticmethod
    def from_dict(data: dict) -> "Metadata":
        return Metadata(update_time=data['updateTime'])

@dataclass
class ContactGroup:
    resource_name: str
    etag: str
    metadata: Optional[Metadata]
    group_type: str
    name: str
    formatted_name: str
    member_count: int
    
    @staticmethod
    def from_dict(data: dict) -> "ContactGroup":
        metadata_instance = Metadata.from_dict(data['metadata']) if data.get('metadata') else None
        return ContactGroup(
            resource_name=data['resourceName'],
            etag=data['etag'],
            metadata=metadata_instance,
            group_type=data['groupType'],
            name=data['name'],
            formatted_name=data['formattedName'],
            member_count=data['memberCount']
        )

class PeopleService:
    """Service class for Google People API operations."""
    
    def __init__(self, service):
        self.service = service
        
    def get_contact_groups(self) -> List[ContactGroup]:
        """Fetch all contact groups."""
        try:
            results = self.service.contactGroups().list().execute()
            contact_groups = []
            
            for group in results.get('contactGroups', []):
                try:
                    contact_groups.append(ContactGroup.from_dict(group))
                except KeyError as e:
                    logging.error(f"Error parsing contact group: {e}")
                    continue
                    
            return contact_groups
        except Exception as e:
            logging.error(f"Error fetching contact groups: {e}")
            raise
            
    def get_keep_groups(self) -> List[ContactGroup]:
        """Get all contact groups that start with 'KEEP'."""
        return [
            group for group in self.get_contact_groups()
            if group.formatted_name == 'KEEP' or group.formatted_name.startswith('KEEP_')
        ]
        
    def get_group_members(self, group: ContactGroup) -> List[str]:
        """Get email addresses of members in a contact group."""
        try:
            # Fetch the detailed group info including member count
            group_detail = self.service.contactGroups().get(
                resourceName=group.resource_name,
                maxMembers=PEOPLE_MAX_MEMBERS
            ).execute()
            
            if not group_detail.get('memberCount', 0):
                return []
                
            # Get the contact details for each member
            members_result = self.service.contactGroups().members().list(
                resourceName=group.resource_name,
                pageSize=PEOPLE_PAGE_SIZE
            ).execute()
            
            email_addresses = []
            for member in members_result.get('memberResourceNames', []):
                try:
                    # Get the contact's details including email addresses
                    person = self.service.people().get(
                        resourceName=member,
                        personFields='emailAddresses'
                    ).execute()
                    
                    # Extract primary email or first available email
                    emails = person.get('emailAddresses', [])
                    if not emails:
                        continue
                        
                    primary_email = next(
                        (email['value'] for email in emails if email.get('metadata', {}).get('primary')),
                        emails[0]['value']
                    )
                    email_addresses.append(primary_email)
                    
                except Exception as e:
                    logging.error(f"Error fetching member details: {e}")
                    continue
                    
            return email_addresses
            
        except Exception as e:
            logging.error(f"Error fetching group members for {group.formatted_name}: {e}")
            return []

    def get_keep_contacts(self) -> Dict[str, List[str]]:
        """Get all contacts with KEEP labels and their email addresses."""
        contacts_by_label = defaultdict(list)
        
        for group in self.get_keep_groups():
            email_addresses = self.get_group_members(group)
            contacts_by_label[group.formatted_name].extend(email_addresses)
            
        return dict(contacts_by_label)

@dataclass
class ContactGroups:
    groups: List[ContactGroup]

    @property
    def cnt(self) -> int:
        return len(self.groups)

    @property
    def group_names(self) -> List[str]:
        return [group.formatted_name for group in self.groups]

def setup_logging():
    """Configure logging with file and console handlers."""
    # Clear any existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
        
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)  # Changed to INFO level
    
    # Create formatters
    file_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    
    # Create a filter to exclude URL request logs
    class URLFilter(logging.Filter):
        def filter(self, record):
            return not record.getMessage().startswith('URL being requested')
    
    try:
        # File Handler with rotation
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding='utf-8'  # Explicitly set encoding
        )
        file_handler.setFormatter(file_formatter)
        file_handler.addFilter(URLFilter())
        root_logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not set up file logging: {e}")
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_handler.addFilter(URLFilter())
    root_logger.addHandler(console_handler)
    
    # Suppress noisy loggers
    logging.getLogger('googleapiclient.discovery').setLevel(logging.WARNING)
    logging.getLogger('google.auth.transport.requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)

def get_oauth_flow():
    """Create and return OAuth 2.0 flow instance."""
    return InstalledAppFlow.from_client_config(
        OAUTH2_CONFIG,
        SCOPES,
        redirect_uri="urn:ietf:wg:oauth:2.0:oob"
    )

def get_credentials():
    """Get valid user credentials from storage or user input."""
    credentials = None
    
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as token:
            credentials = pickle.load(token)
    
    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            try:
                credentials.refresh(Request())
            except Exception as e:
                logging.error(f"Error refreshing credentials: {e}")
                os.remove(TOKEN_FILE)
                return get_credentials()
        else:
            flow = get_oauth_flow()
            credentials = flow.run_local_server(port=0)
            
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(credentials, token)
    
    return credentials

def get_keep_contactgroups_emailaddrs(service) -> Dict[str, List[str]]:
    """Get list of email addresses for each 'KEEP' group."""

    people_service = PeopleService(service)
    keep_groups_emailaddrs = people_service.get_keep_contacts()
    
    logging.info("Contacts by KEEP label:")
    logging.info(json.dumps(keep_groups_emailaddrs, indent=2))
    
    return keep_groups_emailaddrs

def get_or_create_gmail_labels(service, required_labels: Set[str]) -> Dict[str, str]:
    """Get or create Gmail labels for each KEEP label."""
    try:
        # Get existing labels
        results = service.users().labels().list(userId='me').execute()
        existing_labels = {label['name']: label['id'] for label in results.get('labels', [])}
        
        label_ids = {}
        for label_name in required_labels:
            if label_name in existing_labels:
                label_ids[label_name] = existing_labels[label_name]
            else:
                # Create new label
                label_body = {
                    'name': label_name,
                    'labelListVisibility': 'labelShow',
                    'messageListVisibility': 'show'
                }
                created_label = service.users().labels().create(userId='me', body=label_body).execute()
                label_ids[label_name] = created_label['id']
        
        return label_ids
    except Exception as e:
        logging.error(f"Error managing Gmail labels: {str(e)}")
        logging.error(traceback.format_exc())
        raise

def get_email_label_requirements(contacts_by_label: Dict[str, List[str]]) -> Dict[str, Set[str]]:
    """Create mapping of email addresses to their required labels."""
    email_labels = defaultdict(set)
    for label, emails in contacts_by_label.items():
        for email in emails:
            email_labels[email].add(label)
    return dict(email_labels)

def verify_gmail_labels(service, email_label_requirements: Dict[str, List[str]]) -> Dict[str, Dict[str, List[str]]]:
    """Verify Gmail labels for each email address."""
    logging.info("Verifying Gmail messages and labels...")
    results = {}
    total = len(email_label_requirements)
    
    for i, (email, required_labels) in enumerate(email_label_requirements.items(), 1):
        logging.info(f"Checking email {i}/{total}: {email}")
        results[email] = {
            'present_labels': [],
            'missing_labels': []
        }
        
        try:
            # Search for messages with this email
            query = f'from:{email} OR to:{email} OR cc:{email} OR bcc:{email}'
            response = service.users().messages().list(userId='me', q=query, maxResults=1).execute()
            
            if not response.get('messages'):
                logging.warning(f"No messages found for {email}")
                results[email]['missing_labels'] = list(required_labels)
                continue
            
            # Get message to check its labels
            msg_id = response['messages'][0]['id']
            msg = service.users().messages().get(userId='me', id=msg_id).execute()
            
            # Get label names for the message
            label_ids = msg.get('labelIds', [])
            labels_response = service.users().labels().list(userId='me').execute()
            label_map = {label['id']: label['name'] for label in labels_response.get('labels', [])}
            present_labels = {label_map.get(label_id) for label_id in label_ids if label_id in label_map}
            
            # Check which required labels are present/missing
            for label in required_labels:
                if label in present_labels:
                    results[email]['present_labels'].append(label)
                else:
                    results[email]['missing_labels'].append(label)
                    
        except Exception as e:
            logging.error(f"Error checking {email}: {str(e)}")
            logging.error(traceback.format_exc())
            results[email]['missing_labels'] = list(required_labels)
    
    return results

def verify_emails_in_gmail(service, emails: List[str]) -> Dict[str, bool]:
    """Verify if emails exist in Gmail messages."""
    logging.info("Verifying email addresses in Gmail messages...")
    results = {}
    total_start_time = time.time()
    total_messages_scanned = 0
    
    if not emails:
        logging.warning("No emails to verify")
        return results
    
    for i, email in enumerate(emails, 1):
        logging.info(f"Checking email {i}/{len(emails)}: {email}")
        start_time = time.time()
        messages_scanned = 0
        
        try:
            # Search for messages with this email that don't have any KEEP labels
            # and are either to or from this contact
            query = (
                f'(from:{email} OR to:{email}) '
                f'-label:KEEP -label:KEEP_* '
                f'-in:chats -in:spam -in:trash'  # Exclude non-email content
            )
            page_token = None
            found = False
            
            while True:
                response = service.users().messages().list(
                    userId='me',
                    q=query,
                    pageToken=page_token,
                    maxResults=500
                ).execute()
                
                messages = response.get('messages', [])
                messages_scanned += len(messages)
                if messages:
                    found = True
                    break
                
                page_token = response.get('nextPageToken')
                if not page_token:
                    break
                    
                time.sleep(0.1)
            
            results[email] = found
            elapsed = time.time() - start_time
            total_messages_scanned += messages_scanned
            logging.info(f"  - Scanned {messages_scanned} messages in {elapsed:.1f} seconds ({messages_scanned/elapsed:.1f} msgs/sec)")
            
        except Exception as e:
            logging.error(f"Error checking {email}: {str(e)}")
            logging.error(traceback.format_exc())
            results[email] = False
    
    # Print overall statistics
    total_time = time.time() - total_start_time
    logging.info("Email Verification Statistics:")
    logging.info(f"Total time: {total_time:.1f} seconds")
    logging.info(f"Total messages scanned: {total_messages_scanned}")
    logging.info(f"Average processing rate: {total_messages_scanned/total_time:.1f} messages/second")
    logging.info(f"Average time per email: {total_time/len(emails):.1f} seconds")
    
    return results

def get_message_count(service, email: str) -> int:
    """Get total number of messages for an email address."""
    query = f'from:{email} OR to:{email} OR cc:{email} OR bcc:{email}'
    try:
        response = service.users().messages().list(userId='me', q=query).execute()
        return response.get('resultSizeEstimate', 0)
    except Exception as e:
        logging.error(f"Error getting message count for {email}: {str(e)}")
        logging.error(traceback.format_exc())
        return 0

def apply_missing_labels(service, email_verification: Dict[str, Dict[str, List[str]]], label_ids: Dict[str, str]) -> Dict[str, Dict]:
    """
    Apply missing labels to Gmail messages.
    Returns a dictionary with statistics for each email.
    """
    stats = {}
    total_messages_processed = 0
    total_labels_applied = 0
    start_time = time.time()

    # Get all Gmail labels once to avoid repeated API calls
    try:
        labels_response = service.users().labels().list(userId='me').execute()
        label_map = {label['name']: label['id'] for label in labels_response.get('labels', [])}
    except Exception as e:
        logging.error(f"Error getting Gmail labels: {str(e)}")
        logging.error(traceback.format_exc())
        return stats

    for email, verification in email_verification.items():
        missing_labels = verification.get('missing_labels', [])
        if not missing_labels:
            continue

        logging.info(f"\nProcessing {email}...")
        if True:  # DRY_RUN
            logging.info(f"DRY RUN: Would apply labels {missing_labels} to messages from {email}")
            continue

        try:
            # Get messages from this email
            query = f'from:{email}'
            messages_response = service.users().messages().list(userId='me', q=query).execute()
            messages = messages_response.get('messages', [])

            if not messages:
                logging.warning(f"No messages found for {email}")
                continue

            stats[email] = {
                'messages_processed': len(messages),
                'labels_applied': len(missing_labels) * len(messages)
            }

            # Process each message
            for message in messages:
                message_id = message['id']
                
                # Get the current labels for this message
                msg = service.users().messages().get(userId='me', id=message_id, format='minimal').execute()
                current_labels = set(msg['labelIds'])
                
                # Add the missing labels using label IDs from our label_map
                new_label_ids = [label_map[label] for label in missing_labels if label in label_map]
                if not new_label_ids:
                    logging.warning(f"No valid label IDs found for labels {missing_labels}")
                    continue
                
                current_labels.update(new_label_ids)
                
                # Modify the message's labels
                service.users().messages().modify(
                    userId='me',
                    id=message_id,
                    body={'addLabelIds': new_label_ids}
                ).execute()
                
                total_messages_processed += 1
                total_labels_applied += len(new_label_ids)
                
            logging.info(f"Applied {len(missing_labels)} labels to {len(messages)} messages for {email}")
            
        except Exception as e:
            logging.error(f"Error processing {email}: {str(e)}")
            logging.error(traceback.format_exc())
            continue

    end_time = time.time()
    duration = end_time - start_time
    
    if not True:  # DRY_RUN
        logging.info(f"\nLabel application complete:")
        logging.info(f"Total messages processed: {total_messages_processed}")
        logging.info(f"Total labels applied: {total_labels_applied}")
        logging.info(f"Time taken: {duration:.2f} seconds")
        if total_messages_processed > 0:
            logging.info(f"Average time per message: {duration/total_messages_processed:.2f} seconds")
    else:
        logging.info("\nDRY RUN complete - no labels were actually applied")
    
    return stats

def get_keep_label_expiry(label_name: str) -> Optional[date]:
    """
    Get the expiration date for a KEEP label by adding the appropriate duration
    to the current date. Returns None for the base KEEP label which does not expire.
    
    Format: KEEP_nu where:
    - n is the number of units
    - u is the unit (D=days, W=weeks, M=months, Y=years)
    
    Examples:
    - KEEP -> None (does not expire)
    - KEEP_7D -> current_date + 7 days
    - KEEP_3M -> current_date + 3 months
    - KEEP_1Y -> current_date + 1 year
    """
    if label_name == 'KEEP':
        return None
        
    match = KEEP_DURATION_PATTERN.match(label_name)
    if not match:
        logging.warning(f"Invalid KEEP label format: {label_name}")
        return None
        
    amount = int(match.group(1))
    unit = match.group(2)
    
    if unit not in TIME_UNITS:
        logging.warning(f"Invalid time unit in label {label_name}: {unit}")
        return None
        
    # Convert the unit to a relativedelta argument
    unit_arg = {TIME_UNITS[unit]: amount}
    return datetime.now().date() + relativedelta(**unit_arg)

def get_thread_expiry_date(gmail_service, thread_id: str, keep_labels_gmail: Dict[str, str]) -> date:
    """
    Determine the latest date a thread can be deleted by examining all emails
    and their 'KEEP' labels within the thread.
    """
    thread = gmail_service.users().threads().get(userId='me', id=thread_id).execute()
    latest_expiry = latest_message = datetime(1900, 1, 1).date()
    
    for message in thread['messages']:
        msg_date = datetime.fromtimestamp(int(message['internalDate']) / 1000).date()
        if msg_date > latest_message:
            latest_message = msg_date
            
        # Get all KEEP labels on this message
        keep_labels = get_keep_labels_on_message(message, keep_labels_gmail)
        
        for label_id, label in keep_labels.items():
            # Get expiry date for this label
            label_expiry = get_keep_label_expiry(label)
            
            # If this is a base KEEP label, thread never expires
            if label_expiry is None:
                return datetime(9999, 12, 31).date()  # Far future date
                
            # Update latest expiry if this label's expiry is later
            if label_expiry > latest_expiry:
                latest_expiry = label_expiry
                
    # If no expiry found, use default expiry (2 weeks from latest message)
    if latest_expiry == datetime(1900, 1, 1).date():
        latest_expiry = latest_message + relativedelta(weeks=2)
        
    return latest_expiry

def get_keep_labels_on_message(message: Dict, keep_labels_gmail: Dict) -> Dict:
    label_ids_message = message.get('labelIds', [])
    return {label_id: keep_labels_gmail[label_id] 
                for label_id in label_ids_message
                    if label_id in keep_labels_gmail.keys()}

def process_expired_threads(gmail_service, dry_run: bool = True):
    """
    Scan all Gmail threads, identify expired ones, and delete them if not in dry_run mode.
    Returns statistics about the operation.
    """
    stats = {
        'threads_processed': 0,
        'threads_expired': 0,
        'threads_deleted': 0,
        'errors': 0
    }
    
    try:
        # First get all Gmail labels
        logging.info("Fetching all GMail labels...")
        labels_response = gmail_service.users().labels().list(userId='me').execute()
        all_labels = labels_response.get('labels', [])
        # logging.info(f"Found {len(all_labels)} total labels")
        # logging.info("All labels:")
        # for label in all_labels:
        #     logging.info(f"Label ID: {label['id']}, Name: {label.get('name', 'NO_NAME')}")
            
        keep_labels_gmail = {label['id']: label['name'] 
                                for label in all_labels
                                    if label.get('name', '') == 'KEEP' or label.get('name', '').startswith('KEEP_')}
        logging.info(f"Found {len(keep_labels_gmail)} 'KEEP' labels in GMail: {', '.join(keep_labels_gmail.values())}")
        
        # Construct query with explicit OR conditions for each KEEP label
        label_conditions = ' OR '.join(label_name for label_name in keep_labels_gmail.values())
        query = f'({label_conditions})'

        # logging.info(f"Searching with query: {specific_query}")
        # specific_results = gmail_service.users().threads().list(
        #     userId='me',
        #     q=specific_query
        # ).execute()
        
        # if 'threads' in specific_results:
        #     logging.info(f"Found {len(specific_results['threads'])} threads matching '{specific_query}'")
        #     # for thread in specific_results['threads']:
        #     #     thread_detail = gmail_service.users().threads().get(
        #     #         userId='me',
        #     #         id=thread['id']
        #     #     ).execute()
        #     #     logging.info(f"Thread ID: {thread['id']}")
        #     #     for message in thread_detail['messages']:
        #     #         keep_labels_message = get_keep_labels_on_message(message, keep_labels_gmail)
        #     #         msg_date = datetime.fromtimestamp(int(message['internalDate']) / 1000)
        #     #         subject = next((h['value'] for h in message['payload']['headers'] 
        #     #                       if h['name'].lower() == 'subject'), 'No subject')
        #     #         logging.info(f"Subject: {subject}")
        #     #         logging.info(f"Message date: {msg_date}, Labels: {', '.join(keep_labels_message.values())}")

        # # Now continue with regular processing
        # query = f"({label_conditions})"  # Update the main query too
        threads = []
        next_page_token = None
        
        while True:
            try:
                # Use maxResults=100 for efficient batch processing
                results = gmail_service.users().threads().list(
                    userId='me',
                    q=query,
                    maxResults=100,
                    pageToken=next_page_token
                ).execute()
                
                if 'threads' in results:
                    threads.extend(results['threads'])
                    stats['threads_processed'] += len(results['threads'])
                
                next_page_token = results.get('nextPageToken')
                if not next_page_token:
                    break
                    
            except Exception as e:
                logging.error(f"Error fetching threads: {str(e)}")
                logging.error(traceback.format_exc())
                stats['errors'] += 1
                # Add exponential backoff
                time.sleep(min(300, 2 ** stats['errors']))
                if stats['errors'] > 5:
                    raise Exception("Too many errors while fetching threads")
                continue

        logging.info(f"Found {len(threads)} threads matching '{query}'")
   
        # Process threads in batches to avoid rate limits
        batch_size = 100
        for i in range(0, len(threads), batch_size):
            batch = threads[i:i + batch_size]
            
            # for thread in batch:
            iterator = iter(batch)
            while True:
                try:
                    thread = next(iterator)
                except StopIteration:
                    break

                try:
                    thread_id = thread['id']
                    # Get full thread details
                    thread_detail = gmail_service.users().threads().get(
                        userId='me',
                        id=thread_id
                    ).execute()
                    
                    logging.debug(f"Thread ID: {thread_id}")
                    # Log all 'KEEP' labels on the thread
                    for message in thread_detail['messages']:
                        logging.debug(f"  message ID: {message['id']}")
                        keep_labels_message = get_keep_labels_on_message(message, keep_labels_gmail)
                        if keep_labels_message:
                            logging.debug(f"  'KEEP' labels: {', '.join(keep_labels_message.values())}")
                    
                    expiry_date = get_thread_expiry_date(gmail_service, thread_id, keep_labels_gmail)
                    
                    if expiry_date is None:
                        logging.debug(f"  thread {thread_id} has  \"KEEP\" label - will not expire")
                        continue
                        
                    # Check if thread has expired
                    now = datetime.now().date()
                    if expiry_date <= now:
                        stats['threads_expired'] += 1
                        # logging.info(f"Thread {thread_id} has expired (expiry: {expiry_date}, now: {now})")
                        
                        trimmed_snippet = message.get('snippet', 'No snippet')[:46] + (' ...' if len(message.get('snippet', 'No snippet')) > 46 else '')
                        logging.info(f"   snippet: {trimmed_snippet}")
                            
                        if dry_run:
                            logging.info(f"   DRY RUN: Thread WOULD have been deleted {thread_id} - (expiry: {expiry_date})")
                        else:
                            try:
                                gmail_service.users().threads().trash(
                                    userId='me',
                                    id=thread_id
                                ).execute()
                                stats['threads_deleted'] += 1
                                logging.info(f"   deleted thread {thread_id} - (expiry: {expiry_date})")
                            except Exception as e:
                                logging.error(f"   ** Error deleting thread {thread_id}: {str(e)}")
                                logging.error(traceback.format_exc())
                                stats['errors'] += 1
                    else:
                        logging.debug(f"   thread will expire at {expiry_date}")

                except Exception as e:
                    logging.error(f"  ** Error processing thread {thread['id']}: {str(e)}")
                    logging.error(traceback.format_exc())
                    stats['errors'] += 1
                    continue
                    
            # Add small delay between batches to avoid rate limits
            time.sleep(1)
    
    except Exception as e:
        logging.error(f"** Error in process_expired_threads: {str(e)}")
        logging.error(traceback.format_exc())
        raise
    
    logging.info("Expired Threads Summary:")
    logging.info(f"  processed: {stats['threads_processed']}")
    logging.info(f"  expired: {stats['threads_expired']}")
    logging.info(f"  deleted: {stats['threads_deleted']}")
    if stats['errors'] > 0:
        logging.warning(f"** Errors encountered: {stats['errors']}")
    
    return stats

def main():
    # Setup logging
    setup_logging()
    
    if True:  # DRY_RUN
        logging.info("Running in DRY RUN mode - no changes will be made")
    
    # Get credentials
    credentials = get_credentials()

    # Create Google API service
    gmail_service = build('gmail', 'v1', credentials=credentials)
    people_service = build('people', 'v1', credentials=credentials)

    # Get contacts with KEEP labels
    people_service_instance = PeopleService(people_service)
    keep_contact_groups_emailaddrs = people_service_instance.get_keep_contacts()
    
    # Get mapping of emails to their required labels
    email_label_requirements = get_email_label_requirements(keep_contact_groups_emailaddrs)
    
    # Create a summary of labels by contact
    labels_by_contact = {}
    for email in email_label_requirements:
        labels_by_contact[email] = sorted(email_label_requirements[email])
    
    logging.info("KEEP labels by contact:")
    logging.info(json.dumps(labels_by_contact, indent=2))
    
    # Get or create all required Gmail labels
    all_required_labels = {label for labels in email_label_requirements.values() for label in labels}
    label_ids = get_or_create_gmail_labels(gmail_service, all_required_labels)
    
    # Verify Gmail labels
    label_verification = verify_gmail_labels(gmail_service, email_label_requirements)
    
    # Print verification results
    logging.info('Gmail Label Verification Results:')
    logging.info('=' * 80)
    
    emails_with_all_labels = 0
    for email, status in label_verification.items():
        logging.info(f'Email: {email}')
        logging.info(f"Required labels: {', '.join(sorted(email_label_requirements[email]))}")
        
        if status['present_labels']:
            logging.info(f"Present labels: {', '.join(sorted(status['present_labels']))}")
        
        if status['missing_labels']:
            logging.info(f"Missing labels: {', '.join(sorted(status['missing_labels']))}")
        else:
            logging.info("All required labels are present!")
            emails_with_all_labels += 1
    
    total_emails = len(label_verification)
    logging.info(f'Summary: {emails_with_all_labels}/{total_emails} emails have all required labels')
    
    # If there are missing labels, apply them
    emails_with_missing = sum(1 for status in label_verification.values() if status['missing_labels'])
    if emails_with_missing:
        logging.info("Applying missing labels to Gmail messages...")
        update_results = apply_missing_labels(gmail_service, label_verification, label_ids)
        
        # Print update summary
        logging.info("Label Update Summary:")
        total_messages = sum(stats['messages_processed'] for stats in update_results.values())
        logging.info(f"Updated {total_messages} messages across {len(update_results)} email addresses")
        
        # Print details for each email
        for email, stats in update_results.items():
            if stats['messages_processed'] > 0:
                logging.info(f"  {email}: {stats['messages_processed']} messages updated")
    
    # Collect all unique email addresses
    all_emails = set()
    for emails in keep_contact_groups_emailaddrs.values():
        all_emails.update(emails)
    
    # Verify emails in Gmail
    email_verification = verify_emails_in_gmail(gmail_service, list(all_emails))
    
    # Print verification results
    logging.info('Email Verification Results:')
    logging.info('Email Address'.ljust(40) + 'Found in Gmail')
    logging.info('-' * 60)
    
    emails_found = 0
    for email, found in email_verification.items():
        status = 'YES' if found else 'NO'
        if found:
            emails_found += 1
        logging.info(f'{email.ljust(40)} {status}')
    
    logging.info(f'Summary: {emails_found}/{len(email_verification)} emails found in Gmail messages')
    
    # Search for threads with specific subject
    query = 'subject:"Shellie White shared 416 Pilates\'s post"'
    threads = gmail_service.users().threads().list(userId='me', q=query).execute()
    
    if 'threads' in threads:
        for thread in threads['threads']:
            thread_detail = gmail_service.users().threads().get(
                userId='me',
                id=thread['id']
            ).execute()
            
            logging.info(f"Found thread with subject matching query. Thread ID: {thread['id']}")
            
            # Log all labels on the thread
            for message in thread_detail['messages']:
                labels = message.get('labelIds', [])
                logging.info(f"Message labels: {', '.join(labels)}")
                
                # Specifically check for KEEP_2D
                if 'KEEP_2D' in labels:
                    logging.info(f"Found KEEP_2D label on message in thread {thread['id']}")
                    
                    # Get message date and calculate expiry
                    msg_date = datetime.fromtimestamp(int(message['internalDate']) / 1000)
                    expiry = msg_date + relativedelta(days=2)
                    logging.info(f"Message date: {msg_date}, Expiry date: {expiry}")

    # Process expired threads
    logging.info("Processing expired threads...")
    expired_threads = process_expired_threads(gmail_service, dry_run=True)
    logging.info("Expired Threads Summary:")
    logging.info(f"Threads processed: {expired_threads['threads_processed']}")
    logging.info(f"Threads expired: {expired_threads['threads_expired']}")
    logging.info(f"Threads deleted: {expired_threads['threads_deleted']}")

if __name__ == '__main__':
    main()
