# Flask Email Sender 📧

A web application built with Flask and Python to send bulk emails from a CSV/Excel list, with real-time progress tracking and reporting. Users can register, log in, upload contact lists, compose emails, optionally add attachments, and monitor the sending process.

## ✨ Features

*   **User Authentication:**
    *   Secure user registration and login.
    *   Session management with CSRF protection.
*   **Bulk Email Sending:**
    *   Upload recipient lists via CSV, XLSX, or XLS files.
    *   Specify the column containing email addresses.
    *   Compose custom email subjects and body content.
*   **Attachment Support:**
    *   Optionally attach a single file to all emails.
    *   Supports any file type for attachments (configurable).
    *   Specify a custom display name for the attachment.
*   **Task-Based Processing:**
    *   Email sending is handled as background-simulated tasks (synchronous in this version, but designed for easy async extension).
    *   Unique task IDs for tracking.
*   **Real-time Progress Monitoring:**
    *   Server-Sent Events (SSE) provide live updates on the email sending progress (emails processed, total, status).
*   **Reporting:**
    *   Generates a CSV report upon task completion detailing the status (sent/failed) for each recipient.
    *   Downloadable reports.
*   **Secure Credential Handling:**
    *   Login passwords are not stored directly (verified using `itsdangerous.Serializer`).
    *   SMTP passwords (user's email password by default) are encrypted before storage in MongoDB using `itsdangerous.URLSafeSerializer` with a salt.
*   **File Management:**
    *   Uploaded files are temporarily stored and cleaned up after task completion.
    *   Reports are stored in a dedicated `reports` folder.
*   **MongoDB Integration:**
    *   Stores user account information.

## 🛠️ Tech Stack

*   **Backend:** Python, Flask
*   **Database:** MongoDB (with Pymongo driver)
*   **File Processing:** Pandas
*   **Security:** Flask-WTF (CSRFProtect), itsdangerous (for tokenization & encryption)
*   **Frontend (Basic):** HTML, JavaScript (for form submission, SSE, and dynamic updates)
*   **Environment Management:** python-dotenv

## ⚙️ Prerequisites

*   Python 3.7+
*   Pip (Python package installer)
*   MongoDB instance (local or cloud-hosted, e.g., MongoDB Atlas)
*   An email account (e.g., Gmail) that allows SMTP access.
    *   **For Gmail:** You'll likely need to enable "Less secure app access" (not recommended for long-term use) or preferably generate an "App Password" for this application.

## 🚀 Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/flask-email-sender.git
    cd flask-email-sender
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    # On Windows
    venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(You'll need to create a `requirements.txt` file. See below)*

4.  **Set up Environment Variables:**
    Create a `.env` file in the root directory of the project and add the following variables. You can copy `.env.example` if you create one.

    ```ini
    # .env file
    SECRET_KEY='your_very_strong_random_secret_key_here' # IMPORTANT: Change this!
    MONGO_URI='mongodb://localhost:27017/flask_email_app_db' # Your MongoDB connection string

    # Optional: For development mode
    FLASK_ENV='development'
    FLASK_APP='app.py' # Or whatever your main Flask app file is named
    ```
    *   Generate a strong `SECRET_KEY` (e.g., using `python -c 'import secrets; print(secrets.token_hex(24))'`).
    *   Update `MONGO_URI` to point to your MongoDB instance. If your URI includes a database name, that will be used; otherwise, `flask_email_app_db` is the default.

5.  **Ensure `templates` directory exists:**
    The application expects HTML templates in a `templates` folder in the root directory. Make sure you have at least:
    *   `templates/login.html`
    *   `templates/register.html`
    *   `templates/index.html`
    *(And any base template if you use one, e.g., `templates/base.html`)*

    The application will create `uploads` and `uploads/reports` directories automatically if they don't exist.

## ▶️ Running the Application

Once the setup is complete, run the Flask development server:

```bash
flask run
# or
python app.py


The application will typically be available at http://127.0.0.1:5001 (or the port specified if flask run is used with --port or if hardcoded in app.run).

📋 requirements.txt

Create a requirements.txt file in the root of your project with the following content:

Flask
Flask-WTF
pymongo[srv] # Use [srv] if connecting to MongoDB Atlas with dns+srv URI
pandas
openpyxl # For .xlsx support with Pandas
python-dotenv
itsdangerous
werkzeug # Usually a Flask dependency, but good to list
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Txt
IGNORE_WHEN_COPYING_END

Then run pip install -r requirements.txt. (Note: smtplib is built-in to Python).

📄 .env.example

It's good practice to include an example environment file:

# .env.example
SECRET_KEY='replace_with_a_strong_random_secret_key'
MONGO_URI='mongodb://localhost:27017/your_app_db_name'
FLASK_ENV='development'
FLASK_APP='app.py'
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
Ini
IGNORE_WHEN_COPYING_END
🧑‍💻 Usage

Register: Navigate to /register to create a new user account. You'll provide an email and a password.

Important: The password you provide during registration will also be used as your SMTP password for sending emails. It's highly recommended to use an App Password from your email provider (like Gmail) instead of your main account password.

Login: Go to /login and sign in with your registered credentials.

Index Page (/index):

Upload Main File: Select your CSV/XLSX/XLS file containing recipient email addresses.

Email Column Name: Enter the exact name of the column in your file that holds the email addresses.

Subject & Body: Compose the email subject and body.

Include Attachment?:

If "Yes", an option to upload a secondary file (attachment) and set a display name will appear.

Submit: Click "Initiate Email Task".

Task Processing:

The page will show real-time progress updates (emails processed, total, status messages).

Download Report:

Once the task is complete (or has failed), a link to download the CSV report will be provided if a report was generated.

🔐 Security Considerations

SECRET_KEY: Ensure SECRET_KEY is strong, random, and kept confidential in production.

SMTP Credentials: The application stores (encrypted) user-provided SMTP passwords. This is a sensitive operation.

STRONGLY RECOMMEND users utilize "App Passwords" (e.g., from Google Accounts) instead of their primary email account password.

Educate users about the risks of providing their main email password.

Database Security: Secure your MongoDB instance appropriately (authentication, network access controls).

Input Validation: The application performs some input validation, but thorough validation is crucial for security.

File Uploads: File types and sizes are restricted. secure_filename is used.

CSRF Protection: Implemented via Flask-WTF.

Production Deployment: For production, do NOT run with the Flask development server. Use a production-grade WSGI server like Gunicorn or uWSGI, often behind a reverse proxy like Nginx.

💡 Future Enhancements / To-Do

Asynchronous task processing (e.g., using Celery with Redis/RabbitMQ) for true non-blocking operations.

More robust error handling and user feedback.

User interface improvements (e.g., using a frontend framework).

Option to preview emails.

Support for multiple attachments.

Admin panel for user management.

Option for users to configure their own SMTP server settings (not just Gmail default).

Unit and integration tests.

Centralized, secure SMTP configuration (e.g., using a dedicated service account) instead of individual user credentials.

🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

Fork the Project

Create your Feature Branch (git checkout -b feature/AmazingFeature)

Commit your Changes (git commit -m 'Add some AmazingFeature')

Push to the Branch (git push origin feature/AmazingFeature)

Open a Pull Request

📄 License

Distributed under the MIT License. See LICENSE file for more information (if you add one).

If you're still having trouble:
1.  Try clicking a "copy" icon if your interface shows one for the code block.
2.  Select the text carefully from within the box.
3.  Copy and paste it into a plain text editor first (like Notepad on Windows, TextEdit in plain text mode on Mac, or VS Code) to ensure it's clean, then save it as `README.md`.
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
IGNORE_WHEN_COPYING_END
