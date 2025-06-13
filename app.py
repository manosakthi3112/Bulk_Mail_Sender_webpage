import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import smtplib
import re
from flask_wtf import CSRFProtect
from itsdangerous import URLSafeSerializer, BadSignature, Serializer

from functools import wraps
from datetime import timedelta, datetime
import json
import uuid # For unique task IDs
import time # For SSE sleep

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import pandas as pd
from dotenv import load_dotenv
# --- MongoDB Integration ---
from pymongo import MongoClient, errors as pymongo_errors
from urllib.parse import urlparse

UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER_NAME = 'reports' # Subfolder for reports
ALLOWED_EXTENSIONS_MAIN = {'csv', 'xlsx', 'xls'}
ALLOWED_EXTENSIONS_SECONDARY = {'*'} # Allows any extension for secondary file

app = Flask(__name__)

# IMPORTANT: Change this in production!
app.secret_key = os.getenv("SECRET_KEY", "change_this_to_a_very_strong_random_secret_key_in_production")
if app.secret_key == "change_this_to_a_very_strong_random_secret_key_in_production" and os.getenv("FLASK_ENV") != "development":
    print("FATAL WARNING: Using default SECRET_KEY in a non-development environment. THIS IS EXTREMELY INSECURE!")

csrf = CSRFProtect(app)
load_dotenv() 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = os.path.join(UPLOAD_FOLDER, REPORTS_FOLDER_NAME)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# --- MongoDB Configuration ---
app.config['MONGO_URI'] = os.getenv("MONGO_URI", "mongodb://localhost:27017/flask_email_app_db")
MONGO_CLIENT = None
# You can make DB_NAME and USERS_COLLECTION_NAME configurable too if needed
DB_NAME_DEFAULT = "flask_email_app_db"  # Default if not in URI
USERS_COLLECTION_NAME = "users"

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

# --- Global Dictionaries for Task Management (for simplicity, not for multi-worker production) ---
app.tasks = {}
app.progress = {}

# --- MongoDB Helper Functions ---
def init_mongodb(current_app):
    global MONGO_CLIENT
    mongo_uri = current_app.config.get('MONGO_URI')
    if not mongo_uri:
        print("FATAL WARNING: MONGO_URI not set in environment or config. MongoDB integration will fail.")
        MONGO_CLIENT = None
        return

    try:
        MONGO_CLIENT = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000) # Added timeout
        MONGO_CLIENT.admin.command('ping') # Test connection
        print(f"Successfully connected to MongoDB at {mongo_uri}.")

        # Optional: Ensure indexes. '_id' is automatically indexed.
        # If you were using a different field for email, you'd create an index:
        # users_collection = get_users_collection()
        # if users_collection is not None:
        #     users_collection.create_index("email_field_name", unique=True)

    except pymongo_errors.ConnectionFailure as e:
        print(f"FATAL ERROR: Could not connect to MongoDB at {mongo_uri}: {e}")
        MONGO_CLIENT = None
    except Exception as e:
        print(f"An unexpected error occurred during MongoDB initialization: {e}")
        MONGO_CLIENT = None

def get_users_collection():
    if MONGO_CLIENT:
        parsed_uri = urlparse(app.config['MONGO_URI'])
        db_name_from_uri = parsed_uri.path.strip('/')
        
        actual_db_name = db_name_from_uri if db_name_from_uri else DB_NAME_DEFAULT
        
        db = MONGO_CLIENT[actual_db_name]
        return db[USERS_COLLECTION_NAME]
    return None

# Call MongoDB initialization after app config is loaded
init_mongodb(app)


def get_login_data_serializer():
    return Serializer(app.secret_key)

def get_smtp_password_serializer():
    return URLSafeSerializer(app.secret_key, salt='smtp-password-encryption-salt')

# --- User Password Management (Logic remains the same, storage changes) ---
def create_login_verification_token(password):
    s = get_login_data_serializer()
    return s.dumps(password)

def verify_login_password(login_token, password_to_check):
    if login_token is None:
        return False
    s = get_login_data_serializer()
    try:
        password_from_token = s.loads(login_token)
        return password_from_token == password_to_check
    except BadSignature:
        return False
    except TypeError: # Handle cases where login_token might not be a string
        return False


def encrypt_smtp_password_for_storage(password):
    s = get_smtp_password_serializer()
    return s.dumps(password)

def decrypt_smtp_password_from_storage(encrypted_password):
    if encrypted_password is None:
        return None
    s = get_smtp_password_serializer()
    try:
        return s.loads(encrypted_password)
    except BadSignature:
        print("ERROR: Failed to decrypt SMTP password (BadSignature). SECRET_KEY/salt might have changed.")
        return None
    except TypeError:
        print(f"TypeError during SMTP password decryption for: '{encrypted_password}'.")
        return None

# --- Login Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if 'smtp_email' not in session or 'smtp_password' not in session:
            # This could happen if SMTP details failed to decrypt post-login or session is partial
            users_collection = get_users_collection()
            user_data = None
            if users_collection:
                try:
                    user_data = users_collection.find_one({'_id': session['user_id']})
                except pymongo_errors.PyMongoError as e:
                    print(f"DB error while re-fetching SMTP details for {session['user_id']}: {e}")
            
            if user_data:
                decrypted_smtp_pass = decrypt_smtp_password_from_storage(user_data.get('smtp_password_encrypted'))
                if decrypted_smtp_pass:
                    session['smtp_email'] = session['user_id'] # Assuming user_id is email
                    session['smtp_password'] = decrypted_smtp_pass
                else:
                    flash('Session credentials missing or invalid. Please log in again.', 'warning')
                    session.clear()
                    return redirect(url_for('login'))
            else:
                flash('Session user not found or DB error. Please log in again.', 'warning')
                session.clear()
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- File Handling Utilities (Unchanged) ---
def allowed_file(filename, allowed_set):
    if not filename: return False
    if '.' not in filename: return False
    name_part, ext_part = filename.rsplit('.', 1)
    if not ext_part: return False
    if allowed_set == {'*'}: return True
    return ext_part.lower() in allowed_set

def cleanup_files(paths_to_delete):
    if paths_to_delete is None: paths_to_delete = []
    for path in paths_to_delete:
        if path and os.path.exists(path):
            try:
                os.remove(path)
                print(f"Cleaned up file: {path}")
            except Exception as e:
                print(f"Error cleaning up file {path}: {e}")

def process_file_upload(file_key_in_request, request_files, allowed_extensions, upload_folder, file_prefix=""):
    user_friendly_name = file_key_in_request.replace("_", " ").capitalize()
    if not request_files:
        print(f'process_file_upload: No files found in request for {file_key_in_request}!')
        return None
    if file_key_in_request not in request_files:
        print(f'process_file_upload: No {user_friendly_name.lower()} part in request!')
        return None
    file_obj = request_files[file_key_in_request]
    if file_obj.filename == '':
        print(f'process_file_upload: No {user_friendly_name.lower()} selected!')
        return None

    if file_obj and allowed_file(file_obj.filename, allowed_extensions):
        filename = secure_filename(file_obj.filename)
        saved_path = os.path.join(upload_folder, file_prefix + filename)
        try:
            file_obj.save(saved_path)
            return saved_path
        except Exception as e:
            print(f'Error saving {user_friendly_name.lower()} "{filename}": {str(e)}')
            return None
    else:
        allowed_ext_str = ", ".join(list(allowed_extensions)) if allowed_extensions != {'*'} else "any type"
        print(f'Invalid file type for {user_friendly_name.lower()} ("{file_obj.filename}"). Allowed: {allowed_ext_str}')
        return None

# --- Email Sending Logic (Unchanged) ---
def msg_sender(subject, body, recipient_email, sender_email_address):
    message = MIMEMultipart()
    message['Subject'] = subject
    message['From'] = sender_email_address
    message['To'] = recipient_email
    message.attach(MIMEText(body, 'plain'))
    return message

def msg_sender_attachment(subject, body, recipient_email, attachment_path, attachment_display_name, sender_email_address):
    message = MIMEMultipart()
    message['Subject'] = subject
    message['From'] = sender_email_address
    message['To'] = recipient_email
    message.attach(MIMEText(body, 'plain'))

    # Safe default values
    if not attachment_path or not os.path.isfile(attachment_path):
        print("Attachment path is invalid or file does not exist.")
        return None

    try:
        original_ext = os.path.splitext(attachment_path)[1]  # includes the dot, e.g., '.pdf'
        if not original_ext:
            print("Warning: attachment file has no extension.")

        # Handle display name
        if attachment_display_name:
            attachment_display_name = re.sub(r'[^\w\-. ]', '', attachment_display_name.strip())
            if '.' not in attachment_display_name and original_ext:
                attachment_display_name += original_ext
            actual_filename_for_mime = attachment_display_name
        else:
            actual_filename_for_mime = os.path.basename(attachment_path)

        with open(attachment_path, 'rb') as file:
            part = MIMEApplication(file.read(), Name=actual_filename_for_mime)

        part.add_header('Content-Disposition', 'attachment', filename=actual_filename_for_mime)
        message.attach(part)

    except Exception as e:
        print(f"Failed to attach file: {e}")
        return None

    return message


def send_email_with_session_credentials(message_obj):
    user_smtp_email = session.get('smtp_email')
    user_smtp_password = session.get('smtp_password')

    if not user_smtp_email or not user_smtp_password:
        msg = 'SMTP credentials not in session.'
        print(f"send_email_with_session_credentials: {msg}")
        return False, msg

    if message_obj['From'] != user_smtp_email:
        message_obj.replace_header('From', user_smtp_email)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server: # Replace with your SMTP server
            server.login(user_smtp_email, user_smtp_password)
            server.send_message(message_obj)
        return True, ""
    except smtplib.SMTPAuthenticationError:
        error_msg = (f"SMTP Auth Error for {user_smtp_email}. Check password/App Password.")
        print(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Error sending email: {e}"
        print(error_msg)
        return False, error_msg

# --- Routes ---
@app.route('/')
def root():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        users_collection = get_users_collection()
        if users_collection is None:
            flash('System error: User database is currently unavailable. Please try again later.', 'danger')
            return render_template('login.html')

        email_form = request.form.get('email', '').strip().lower()
        password_form = request.form.get('password', '')
        user_data = None
        
        try:
            user_data = users_collection.find_one({'_id': email_form}) # Using email as _id
        except pymongo_errors.PyMongoError as e:
            print(f"MongoDB error during login for {email_form}: {e}")
            flash('Database error during login. Please try again.', 'danger')
            return render_template('login.html')

        if user_data and verify_login_password(user_data.get('login_verification_token'), password_form):
            session.permanent = True
            session['user_id'] = user_data['_id'] # email_form
            decrypted_smtp_pass = decrypt_smtp_password_from_storage(user_data.get('smtp_password_encrypted'))
            if decrypted_smtp_pass:
                session['smtp_email'] = user_data['_id']
                session['smtp_password'] = decrypted_smtp_pass
                flash('Logged in successfully.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Login successful, but there was an issue retrieving email sending credentials. Please re-register or contact support if this persists.', 'danger')
                session.clear() # Clear partial session
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        users_collection = get_users_collection()
        if users_collection is None:
            flash('System error: User database is currently unavailable. Please try again later.', 'danger')
            return render_template('register.html')

        email_form = request.form.get('email', '').strip().lower()
        password_form = request.form.get('password', '')

        if not email_form or not password_form:
            flash('Email and password cannot be empty.', 'warning')
            return render_template('register.html')
        if "@" not in email_form or "." not in email_form.split('@')[-1] or len(email_form.split('@')) != 2 :
            flash('Invalid email format.', 'warning')
            return render_template('register.html')

        try:
            # Check if user email (which we use as _id) exists
            if users_collection.count_documents({'_id': email_form}, limit=1) > 0:
                flash('Email already registered.', 'error')
                return render_template('register.html')
        except pymongo_errors.PyMongoError as e:
            print(f"MongoDB error during user existence check for {email_form}: {e}")
            flash('Database error during registration. Please try again.', 'danger')
            return render_template('register.html')

        user_document = {
            '_id': email_form, # Using email as the document's unique ID
            'login_verification_token': create_login_verification_token(password_form),
            'smtp_password_encrypted': encrypt_smtp_password_for_storage(password_form), # Using the same password for SMTP
            'registered_at': datetime.utcnow()
        }

        try:
            users_collection.insert_one(user_document)
            flash('Account created. Please log in.', 'success')
            flash(f'Password for {email_form} will be used for SMTP.', 'info') # Inform user
            return redirect(url_for('login'))
        except pymongo_errors.DuplicateKeyError:
            # Should be caught by count_documents, but as a safeguard
            flash('Email already registered (concurrent attempt?).', 'error')
            return render_template('register.html')
        except pymongo_errors.PyMongoError as e:
            print(f"MongoDB error during user insertion for {email_form}: {e}")
            flash('Database error during account creation. Please try again.', 'danger')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        errors = []

        main_file_obj = request.files.get('main_file')
        column_name = request.form.get('column_name', '').strip()
        subject_content = request.form.get('extra_input_Subject_content', '').strip()

        if not main_file_obj or main_file_obj.filename == '':
            errors.append('Main contact file is required.')
        elif not allowed_file(main_file_obj.filename, ALLOWED_EXTENSIONS_MAIN):
            errors.append(f'Invalid file type for main contact file. Allowed: {", ".join(ALLOWED_EXTENSIONS_MAIN)}')

        if not column_name:
            errors.append('Email column name cannot be empty.')
        if not subject_content:
            errors.append('Email subject cannot be empty.')

        secondary_file_obj = request.files.get('secondary_file')
        conditional_choice = request.form.get('conditional_choice')
        if conditional_choice == 'yes':
            if not secondary_file_obj or secondary_file_obj.filename == '':
                errors.append('Attachment file is required when "Include an Attachment?" is Yes.')
            elif ALLOWED_EXTENSIONS_SECONDARY != {'*'} and not allowed_file(secondary_file_obj.filename, ALLOWED_EXTENSIONS_SECONDARY):
                errors.append(f'Invalid file type for attachment. Allowed: {", ".join(ALLOWED_EXTENSIONS_SECONDARY) if ALLOWED_EXTENSIONS_SECONDARY != {"*"} else "any type with an extension"}')
            elif ALLOWED_EXTENSIONS_SECONDARY == {'*'} and (not secondary_file_obj.filename or '.' not in secondary_file_obj.filename):
                 errors.append('Attachment file must have an extension if all types are allowed.')


        if errors:
            return jsonify({'errors': errors, 'message': 'Validation failed. Please correct the issues.'}), 400

        task_id = uuid.uuid4().hex
        main_file_saved_path = process_file_upload(
            'main_file', request.files, ALLOWED_EXTENSIONS_MAIN,
            app.config['UPLOAD_FOLDER'], f"main_{task_id}_"
        )
        if not main_file_saved_path:
            return jsonify({'errors': ['Failed to save main file during processing.'], 'message': 'File system error.'}), 500

        body_content = request.form.get('extra_input_body_content', '')
        secondary_file_saved_path = None
        attachment_custom_name = None
        if conditional_choice == 'yes':
            secondary_file_saved_path = process_file_upload(
                'secondary_file', request.files, ALLOWED_EXTENSIONS_SECONDARY,
                app.config['UPLOAD_FOLDER'], f"secondary_{task_id}_"
            )
            if not secondary_file_saved_path:
                cleanup_files([main_file_saved_path])
                return jsonify({'errors': ['Failed to save attachment file during processing.'], 'message': 'File system error.'}), 500
            attachment_custom_name = request.form.get('attachment_display_name', '').strip()

        app.tasks[task_id] = {
            'user_id': session['user_id'],
            'main_file_path': main_file_saved_path,
            'column_name': column_name,
            'body_content': body_content,
            'subject_content': subject_content,
            'conditional_choice': conditional_choice,
            'secondary_file_path': secondary_file_saved_path,
            'attachment_custom_name': attachment_custom_name,
            'files_to_cleanup_post_task': [p for p in [main_file_saved_path, secondary_file_saved_path] if p]
        }
        app.progress[task_id] = {
            'user_id': session['user_id'], 'current': 0, 'total': 0,
            'status': 'queued', 'messages': [], 'report_filename': None,
            'overall_status_message': 'Task queued. Waiting to start processing...'
        }
        return jsonify({'task_id': task_id, 'message': 'Task initiated successfully.'}), 200

    return render_template('index.html')


@app.route('/execute-task/<task_id>', methods=['POST'])
@login_required
def execute_task(task_id):
    task_params = app.tasks.get(task_id)
    if not task_params or task_params.get('user_id') != session['user_id']:
        return jsonify({'error': 'Task not found or unauthorized'}), 403

    progress_entry = app.progress.get(task_id)
    if not progress_entry :
        if task_params: # Should not happen if task_params exists
            app.progress[task_id] = {
                'user_id': session['user_id'], 'current': 0, 'total': 0,
                'status': 'queued', 'messages': [], 'report_filename': None,
                'overall_status_message': 'Task (re)queued. Progress entry was missing.'
            }
            progress_entry = app.progress.get(task_id)
            print(f"Warning: Progress entry for task {task_id} was missing, re-initialized.")
        else: # Should be caught by the first check
            return jsonify({'error': 'Task data inconsistent.'}), 500

    if progress_entry.get('status') == 'processing':
         return jsonify({'error': 'Task already processing.'}), 409
    if progress_entry.get('status') in ['completed', 'failed']:
         return jsonify({'error': f'Task already {progress_entry.get("status")}. Cannot re-execute.'}), 409


    progress_entry['status'] = 'processing'
    progress_entry['overall_status_message'] = 'Processing started...'

    main_file_path = task_params['main_file_path']
    column_name = task_params['column_name']

    report_data = []
    emails_sent_count = 0
    emails_failed_count = 0

    df = None
    try:
        file_extension = os.path.splitext(main_file_path)[1].lower()
        if file_extension == '.csv': df = pd.read_csv(main_file_path)
        elif file_extension in ['.xlsx', '.xls']: df = pd.read_excel(main_file_path)
        else:
            raise ValueError(f'Unsupported main file type: {file_extension}')

        if df is None or df.empty:
            raise ValueError('Main file is empty or could not be read.')
        if column_name not in df.columns:
            raise ValueError(f'Column "{column_name}" not found in file.')

        valid_emails_series = df[column_name].dropna().astype(str).str.strip()
        valid_emails_series = valid_emails_series[valid_emails_series.str.contains("@")]

        progress_entry['total'] = len(valid_emails_series)
        
        # Capture session data for this batch, as session context might change
        # if this function were to be run in a separate thread/worker without Flask context
        # For current synchronous execution, session['smtp_email'] is fine.
        sender_for_this_batch = session['smtp_email']

        if progress_entry['total'] > 0:
            for idx, recipient_email_raw in valid_emails_series.items():
                if progress_entry['status'] == 'failed': # Check if a critical error occurred mid-process
                    print(f"Task {task_id} processing aborted due to earlier failure.")
                    break

                recipient_email = str(recipient_email_raw).strip()
                message_obj = None
                if task_params['conditional_choice'] == 'yes' and task_params['secondary_file_path']:
                    message_obj = msg_sender_attachment(
                        task_params['subject_content'], task_params['body_content'], recipient_email,
                        task_params['secondary_file_path'], task_params['attachment_custom_name'],
                        sender_for_this_batch
                    )
                else:
                    message_obj = msg_sender(
                        task_params['subject_content'], task_params['body_content'], recipient_email,
                        sender_for_this_batch
                    )

                email_status_detail = "Failed: Unknown error"
                success = False
                error_detail_for_report = ""
                if message_obj:
                    # send_email_with_session_credentials uses global session by design here
                    success, error_detail_for_report = send_email_with_session_credentials(message_obj)
                    if success:
                        emails_sent_count += 1
                        email_status_detail = "Sent successfully"
                    else:
                        emails_failed_count += 1
                        email_status_detail = f"Failed: {error_detail_for_report}"
                else:
                    emails_failed_count += 1
                    email_status_detail = "Failed: Could not construct email (attachment issue?)"
                    error_detail_for_report = email_status_detail

                report_data.append({
                    'Recipient': recipient_email,
                    'Status': "Sent" if success else "Failed",
                    'Details': error_detail_for_report,
                    'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                progress_entry['current'] = emails_sent_count + emails_failed_count
                # No need to yield progress here, SSE endpoint handles that

    except Exception as e:
        progress_entry['status'] = 'failed'
        progress_entry['overall_status_message'] = f'Critical error during email processing: {str(e)}'
        print(f"Task {task_id} failed critically: {str(e)}")
        # Add to report_data if possible
        report_data.append({
            'Recipient': 'N/A - System Error',
            'Status': "Failed",
            'Details': f'Critical processing error: {str(e)}',
            'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

    finally:
        report_df = pd.DataFrame(report_data)
        report_filename_base = f"report_{task_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
        report_filepath = os.path.join(app.config['REPORTS_FOLDER'], report_filename_base)

        if not report_df.empty:
            try:
                report_df.to_csv(report_filepath, index=False)
                progress_entry['report_filename'] = report_filename_base
                print(f"Report generated: {report_filepath}")
            except Exception as e_report:
                print(f"Error generating report for task {task_id}: {e_report}")
                current_msg = progress_entry.get('overall_status_message', 'Task Processing Issue')
                progress_entry['overall_status_message'] = f"{current_msg} | Error generating status report."
        elif progress_entry.get('total', 0) == 0 and progress_entry.get('status') != 'failed':
             # Case: No valid emails to process, but task itself didn't fail critically.
            progress_entry['overall_status_message'] = 'No valid email addresses found to process.'
            if progress_entry['status'] != 'failed': progress_entry['status'] = 'completed'
        
        # Determine final status if not already set to 'failed' by a critical error
        if progress_entry['status'] != 'failed':
             progress_entry['status'] = 'completed'

        # Consolidate overall status message
        if progress_entry['status'] == 'failed':
            # Prepend the critical error if it was the cause, otherwise use current message
            base_fail_msg = progress_entry.get('overall_status_message', 'Task failed')
            summary_part = f" (Processed {progress_entry.get('current',0)} of {progress_entry.get('total',0)} before critical failure: {emails_sent_count} sent, {emails_failed_count} individual fails)."
            progress_entry['overall_status_message'] = base_fail_msg + summary_part
        else: # Completed
            if progress_entry.get('total', 0) == 0:
                 progress_entry['overall_status_message'] = 'Task completed. No valid email addresses found to process.'
            else:
                progress_entry['overall_status_message'] = f'Task completed. Sent: {emails_sent_count}, Failed: {emails_failed_count} (out of {progress_entry.get("total",0)} valid emails).'

        if progress_entry.get('report_filename'):
            progress_entry['overall_status_message'] += f' Report "{progress_entry["report_filename"]}" available.'
        # Consider case where processing happened, but report failed to generate
        elif progress_entry.get('total',0) > 0 and progress_entry['status'] == 'completed' and (emails_sent_count + emails_failed_count > 0):
             progress_entry['overall_status_message'] += ' Report generation might have failed or no specific errors to report if all sent.'


        cleanup_files(task_params.get('files_to_cleanup_post_task', []))
        app.tasks.pop(task_id, None) # Remove task definition after processing

    return jsonify({
        'status': progress_entry['status'],
        'message': progress_entry['overall_status_message'],
        'report': progress_entry.get('report_filename')
    })


@app.route('/stream-progress/<task_id>')
@login_required
def stream_progress(task_id):
    session_user_id = session.get('user_id')
    if not session_user_id:
        def early_exit_stream():
            yield f"data: {json.dumps({'status': 'error', 'message': 'User session not found for stream.'})}\n\n"
        return Response(early_exit_stream(), mimetype='text/event-stream')

    def generate():
        last_sent_progress_str = None
        while True:
            # It's important that app.progress is thread-safe if you move to multi-threading/workers
            # For Flask's default single-worker, single-thread model, direct access is fine.
            current_progress = app.progress.get(task_id)
            
            if not current_progress or current_progress.get('user_id') != session_user_id:
                yield f"data: {json.dumps({'status': 'error', 'message': 'Task not found or stream access denied for your session.'})}\n\n"
                break

            current_progress_str = json.dumps(current_progress)
            if current_progress_str != last_sent_progress_str:
                yield f"data: {current_progress_str}\n\n"
                last_sent_progress_str = current_progress_str

            if current_progress.get('status') in ['completed', 'failed']:
                break
            time.sleep(0.5) # Polling interval
    return Response(generate(), mimetype='text/event-stream')

@app.route('/download-report/<filename>')
@login_required
def download_report(filename):
    can_download = False
    # Check if the current user owns a task that generated this report
    for task_prog in app.progress.values(): # Iterate through values directly
        if task_prog.get('user_id') == session['user_id'] and task_prog.get('report_filename') == filename:
            can_download = True
            break

    if not can_download:
        flash("Report not found or access denied.", "danger")
        return redirect(url_for('index'))

    try:
        # Secure filename again just in case, although it should be safe from progress entry
        return send_from_directory(app.config['REPORTS_FOLDER'], secure_filename(filename), as_attachment=True)
    except FileNotFoundError:
        flash("Report file not found on server.", "error")
        return redirect(url_for('index'))

@app.context_processor
def utility_processor():
    # {{ csrf_token() }} is preferred in templates directly.
    # This processor can be used for other global template utilities if needed.
    return dict()

if __name__ == '__main__':
    print("\n" + "="*80)
    print("                Flask Email Sender Application Starting")
    print(f"Flask App Name: {app.name}")
    print(f"Debug Mode: {app.debug}")
    secret_key_status = "Yes (Custom)" if app.secret_key != "change_this_to_a_very_strong_random_secret_key_in_production" else "NO - USING DEFAULT (INSECURE!)"
    print(f"Secret Key Set: {secret_key_status}")
    
    # MongoDB Info
    print(f"MongoDB URI: {app.config.get('MONGO_URI', 'Not Set')}")
    if MONGO_CLIENT:
        parsed_uri_main = urlparse(app.config['MONGO_URI'])
        db_name_from_uri_main = parsed_uri_main.path.strip('/')
        actual_db_name_main = db_name_from_uri_main if db_name_from_uri_main else DB_NAME_DEFAULT
        print(f"MongoDB Database: {actual_db_name_main}")
        print(f"MongoDB Users Collection: {USERS_COLLECTION_NAME}")
    else:
        print("MongoDB Connection: FAILED (Check logs and MONGO_URI)")

    print(f"Upload Folder: {os.path.abspath(app.config['UPLOAD_FOLDER'])}")
    print(f"Reports Folder: {os.path.abspath(app.config['REPORTS_FOLDER'])}")
    print(f"Max Upload Size: {app.config['MAX_CONTENT_LENGTH'] / (1024*1024):.2f} MB")
    print(f"Session Lifetime: {app.config['PERMANENT_SESSION_LIFETIME']}")
    print("="*80 + "\n")

    templates_dir = "templates" # Assuming templates are in a 'templates' folder
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
        print(f"Created directory: {templates_dir}")

    required_templates = ["login.html", "register.html", "index.html"] # Add base.html if you use one
    for tmpl in required_templates:
        if not os.path.exists(os.path.join(templates_dir, tmpl)):
            print(f"WARNING: Template '{tmpl}' not found in '{templates_dir}'. Application might not work correctly.")

    print("Ensure your HTML templates are present in the 'templates' directory.")
    print("Use `{{ get_flashed_messages(with_categories=true) }}` for messages and")
    print("`{{ csrf_token() }}` directly in forms for CSRF protection.")
    print("Make sure you have a MongoDB instance running and accessible via MONGO_URI.")
    print("Install pymongo: pip install pymongo dnspython (dnspython for mongodb+srv URIs)")


    app.run(debug=True, port=5001)
