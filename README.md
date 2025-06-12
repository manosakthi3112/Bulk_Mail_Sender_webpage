#Bulk Email Sender Webpage
## ⚙️ How It Works

This application allows users to send bulk emails efficiently. Here's the general workflow:

1.  **User Authentication:**
    *   Users **register** with an email and password. This email becomes their username.
    *   The provided password is used for **login** and is also (after encryption) stored to be used as the **SMTP password** for sending emails from their account.
    *   Registered users can **login** to access the application.

2.  **Email Campaign Setup (Index Page):**
    *   **Upload Contact List:** Users upload a primary file (CSV, XLSX, or XLS) containing a list of email addresses.
    *   **Specify Email Column:** They indicate which column in the file contains the recipient email addresses.
    *   **Compose Email:** Users provide the email subject and body content.
    *   **Optional Attachment:** Users can choose to include a single file as an attachment. If "Yes," they upload the attachment file and can provide a custom display name for it.

3.  **Task Initiation & Processing:**
    *   Upon submission, an email-sending "task" is created.
    *   The application processes the contact list:
        *   It reads the email addresses from the specified column using **Pandas**.
        *   For each valid email address, it constructs an email message (using Python's `email.mime` modules).
        *   If an attachment was provided, it's added to each email.
    *   Emails are sent one by one using **smtplib** via SSL (configured for `smtp.gmail.com` by default), authenticating with the user's stored (and decrypted for use) SMTP credentials.

4.  **Real-time Feedback:**
    *   While the task is processing, the user receives real-time progress updates on the webpage via **Server-Sent Events (SSE)**. This includes the number of emails processed, the total number to be sent, and status messages.

5.  **Reporting & Cleanup:**
    *   Once all emails are processed (or if a critical error occurs), a **CSV report** is generated. This report details the status (e.g., "Sent," "Failed") for each recipient, along with any error messages.
    *   The user can **download** this report.
    *   Temporary uploaded files (contact list, attachment) are automatically deleted from the server.

6.  **Data Storage:**
    *   User account details (email as `_id`, a hashed token for login verification, and the encrypted SMTP password) are stored in a **MongoDB** database.

## 📋 Requirements

To run and use this application, you'll need:

**Software & Services:**

1.  **Python:** Version 3.7 or higher.
2.  **Pip:** Python package installer (usually comes with Python).
3.  **MongoDB Instance:** A running MongoDB server (local or cloud-hosted like MongoDB Atlas). The connection URI needs to be configured.
4.  **SMTP-Enabled Email Account:** An email account (e.g., Gmail, Outlook.com, or a custom domain email) that allows SMTP access for sending emails.
    *   **For Gmail:** You will likely need to enable "Less secure app access" (not recommended for production) or, preferably, generate an "App Password" specifically for this application.

**Key Python Libraries (to be installed via `pip`):**

*   `Flask`: The web framework.
*   `Flask-WTF`: For web forms and CSRF protection.
*   `pymongo`: The official MongoDB driver for Python. (Use `pymongo[srv]` if connecting to MongoDB Atlas with a `mongodb+srv://` URI).
*   `pandas`: For reading and processing CSV/Excel files.
*   `openpyxl`: Required by Pandas to handle `.xlsx` Excel files.
*   `python-dotenv`: For managing environment variables from a `.env` file.
*   `itsdangerous`: For securely signing/serializing data (used for login tokens and encrypting SMTP passwords).
*   `Werkzeug`: A WSGI utility library (usually a dependency of Flask, but good to be aware of).

**(Note: `smtplib`, `email.mime`, `os`, `uuid`, `time`, `json`, `datetime`, `functools`, `urllib.parse` are part of Python's standard library and do not need separate installation.)**

**Environment Configuration:**

*   A `.env` file (or system environment variables) to store:
    *   `SECRET_KEY`: A strong, random secret for Flask session security and data signing.
    *   `MONGO_URI`: The connection string for your MongoDB instance.
