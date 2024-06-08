import os
import re
import sys
from collections import defaultdict

def print_ascii_art():
    ascii_art = """

   _             ___             _                    _            
  (_)___        / __\ __ ___  __| | /\  /\_   _ _ __ | |_ ___ _ __ 
  | / __|_____ / / | '__/ _ \/ _` |/ /_/ / | | | '_ \| __/ _ \ '__|
  | \__ \_____/ /__| | |  __/ (_| / __  /| |_| | | | | ||  __/ |   
 _/ |___/     \____/_|  \___|\__,_\/ /_/  \__,_|_| |_|\__\___|_|   
|__/                                                               
-------------------------------------------------------------------
			Script By: Abdul Samad - ABStronics
 		  	Visit: https://abstronics.com
-------------------------------------------------------------------
    """
    print(ascii_art)

def search_keywords_in_files(directory_path, keywords):
    # Compile regex for faster matching
    keywords_regex = re.compile("|".join([re.escape(keyword) for keyword in keywords]), re.IGNORECASE)

    # Dictionary to hold matched files grouped by keyword
    matched_files = defaultdict(list)

    # Iterate over each file in the directory
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            # Read the content of the file
            with open(file_path, 'r') as file:
                content = file.read()

            # Search for keywords in the content
            for keyword in keywords:
                if re.search(re.escape(keyword), content, re.IGNORECASE):
                    matched_files[keyword].append(filename)

    return matched_files

def main(directory_path):
    # Define the keywords
    keywords = [
        "aws_access_key=", "aws_secret_key=", "api_key=", "passwd=", "pwd=", "heroku=", "slack=", "firebase=", "swagger=", "aws_key=", "password=", "ftp_password=", "jdbc=", "db=", "sql=", "secret=", "jet=", "config=", "admin=", "json=", "gcp=", "htaccess=", " .env=", "ssh_key=", " .git=", "access_key=", "secret_token=", "oauth_token=", "oauth_token_secret=", "user=", "username=", "key=", "private_key=", "client_secret=", "client_id=", "bearer_token=", "token=", "api_secret=", "root_password=", "admin_password=", "db_password=", "mongo_uri=", "redis_url=", "smtp_password=", "smtp_user=", "smtp_username=", "ftp_user=", "ssh_passphrase=", "aws_access_key_id=", "aws_secret_access_key=", "db_uri=", "auth_key=", "auth_token=", "auth_secret=", "ftp_login=", "encryption_key=", "decryption_key=", "signing_key=", "verification_key=", "connection_string=", "db_conn=", "api_key_secret=", "service_account=", "api_token=", "jwt_secret=", "api_client_secret=", "oauth_client_id=", "oauth_client_secret=", "app_secret=", "session_key=", "csrf_token=", "csrf_secret=", "webhook_url=", "webhook_secret=", "sns_topic=", "s3_bucket=", "firebase_api_key=", "google_api_key=", "google_client_id=", "google_client_secret=", "facebook_api_key=", "facebook_app_secret=", "twitter_api_key=", "twitter_api_secret=", "linkedin_client_id=", "linkedin_client_secret=", "github_client_id=", "github_client_secret=", "bitbucket_client_id=", "bitbucket_client_secret=", "heroku_api_key=", "pagerduty_api_key=", "datadog_api_key=", "splunk_api_key=", "rollbar_access_token=", "newrelic_api_key=", "newrelic_app_id=", "sentry_dsn=", "travis_token=", "circleci_token=", "aws_access_key=", "aws_secret_key=", "api key=", "passwd=", "pwd=", "heroku=", "slack=", "firebase=", "swagger=", "aws_secret_key=", "aws key=", "password=", "ftp password=", "jdbc=", "db=", "sql=", "secret jet=", "config=", "admin=", "pwd=", "json=", "gcp=", "htaccess=", " .env=", "ssh key=", " .git=", "access key=", "secret token=", "oauth_token=", "oauth_token_secret=", "user=", "name=", "aws_access_key:", "aws_secret_key:", "api_key:", "passwd:", "pwd:", "heroku:", "slack:", "firebase:", "swagger:", "aws_key:", "password:", "ftp_password:", "jdbc:", "db:", "sql:", "secret:", "jet:", "config:", "admin:", "json:", "gcp:", "htaccess:", " .env:", "ssh_key:", " .git:", "access_key:", "secret_token:", "oauth_token:", "oauth_token_secret:", "user:", "username:", "key:", "private_key:", "client_secret:", "client_id:", "bearer_token:", "token:", "api_secret:", "root_password:", "admin_password:", "db_password:", "mongo_uri:", "redis_url:", "smtp_password:", "smtp_user:", "smtp_username:", "ftp_user:", "ssh_passphrase:", "aws_access_key_id:", "aws_secret_access_key:", "db_uri:", "auth_key:", "auth_token:", "auth_secret:", "ftp_login:", "encryption_key:", "decryption_key:", "signing_key:", "verification_key:", "connection_string:", "db_conn:", "api_key_secret:", "service_account:", "api_token:", "jwt_secret:", "api_client_secret:", "oauth_client_id:", "oauth_client_secret:", "app_secret:", "session_key:", "csrf_token:", "csrf_secret:", "webhook_url:", "webhook_secret:", "sns_topic:", "s3_bucket:", "firebase_api_key:", "google_api_key:", "google_client_id:", "google_client_secret:", "facebook_api_key:", "facebook_app_secret:", "twitter_api_key:", "twitter_api_secret:", "linkedin_client_id:", "linkedin_client_secret:", "github_client_id:", "github_client_secret:", "bitbucket_client_id:", "bitbucket_client_secret:", "heroku_api_key:", "pagerduty_api_key:", "datadog_api_key:", "splunk_api_key:", "rollbar_access_token:", "newrelic_api_key:", "newrelic_app_id:", "sentry_dsn:", "travis_token:", "circleci_token:", "aws_access_key:", "aws_secret_key:", "api key:", "passwd:", "pwd:", "heroku:", "slack:", "firebase:", "swagger:", "aws_secret_key:", "aws key:", "password:", "ftp password:", "jdbc:", "db:", "sql:", "secret jet:", "config:", "admin:", "pwd:", "json:", "gcp:", "htaccess:", " .env:", "ssh key:", " .git:", "access key:", "secret token:", "oauth_token:", "oauth_token_secret:", "user:", "name:", "aws_access_key=", "aws_secret_key=", "api_key=", "passwd=", "pwd=", "heroku=", "slack=", "firebase=", "swagger=", "aws_key=", "password=", "ftp_password=", "jdbc=", "db=", "sql=", "secret=", "jet=", "config=", "admin=", "json=", "gcp=", "htaccess=", " .env=", "ssh_key=", " .git=", "access_key=", "secret_token=", "oauth_token=", "oauth_token_secret=", "user=", "username=", "key=", "private_key=", "client_secret=", "client_id=", "bearer_token=", "token=", "api_secret=", "root_password=", "admin_password=", "db_password=", "mongo_uri=", "redis_url=", "smtp_password=", "smtp_user=", "smtp_username=", "ftp_user=", "ssh_passphrase=", "aws_access_key_id=", "aws_secret_access_key=", "db_uri=", "auth_key=", "auth_token=", "auth_secret=", "ftp_login=", "encryption_key=", "decryption_key=", "signing_key=", "verification_key=", "connection_string=", "db_conn=", "api_key_secret=", "service_account=", "api_token=", "jwt_secret=", "api_client_secret=", "oauth_client_id=", "oauth_client_secret=", "app_secret=", "session_key=", "csrf_token=", "csrf_secret=", "webhook_url=", "webhook_secret=", "sns_topic=", "s3_bucket=", "firebase_api_key=", "google_api_key=", "google_client_id=", "google_client_secret=", "facebook_api_key=", "facebook_app_secret=", "twitter_api_key=", "twitter_api_secret=", "linkedin_client_id=", "linkedin_client_secret=", "github_client_id=", "github_client_secret=", "bitbucket_client_id=", "bitbucket_client_secret=", "heroku_api_key=", "pagerduty_api_key=", "datadog_api_key=", "splunk_api_key=", "rollbar_access_token=", "newrelic_api_key=", "newrelic_app_id=", "sentry_dsn=", "travis_token=", "circleci_token=", "aws_access_key=", "aws_secret_key=", "api key=", "passwd=", "pwd=", "heroku=", "slack=", "firebase=", "swagger=", "aws_secret_key=", "aws key=", "password=", "ftp password=", "jdbc=", "db=", "sql=", "secret jet=", "config=", "admin=", "pwd=", "json=", "gcp=", "htaccess=", " .env=", "ssh key=", " .git=", "access key=", "secret token=", "oauth_token=", "oauth_token_secret=", "user=", "name=", "aws_access_key:", "aws_secret_key:", "api_key:", "passwd:", "pwd:", "heroku:", "slack:", "firebase:", "swagger:", "aws_key:", "password:", "ftp_password:", "jdbc:", "db:", "sql:", "secret:", "jet:", "config:", "admin:", "json:", "gcp:", "htaccess:", " .env:", "ssh_key:", " .git:", "access_key:", "secret_token:", "oauth_token:", "oauth_token_secret:", "user:", "username:", "key:", "private_key:", "client_secret:", "client_id:", "bearer_token:", "token:", "api_secret:", "root_password:", "admin_password:", "db_password:", "mongo_uri:", "redis_url:", "smtp_password:", "smtp_user:", "smtp_username:", "ftp_user:", "ssh_passphrase:", "aws_access_key_id:", "aws_secret_access_key:", "db_uri:", "auth_key:", "auth_token:", "auth_secret:", "ftp_login:", "encryption_key:", "decryption_key:", "signing_key:", "verification_key:", "connection_string:", "db_conn:", "api_key_secret:", "service_account:", "api_token:", "jwt_secret:", "api_client_secret:", "oauth_client_id:", "oauth_client_secret:", "app_secret:", "session_key:", "csrf_token:", "csrf_secret:", "webhook_url:", "webhook_secret:", "sns_topic:", "s3_bucket:", "firebase_api_key:", "google_api_key:", "google_client_id:", "google_client_secret:", "facebook_api_key:", "facebook_app_secret:", "twitter_api_key:", "twitter_api_secret:", "linkedin_client_id:", "linkedin_client_secret:", "github_client_id:", "github_client_secret:", "bitbucket_client_id:", "bitbucket_client_secret:", "heroku_api_key:", "pagerduty_api_key:", "datadog_api_key:", "splunk_api_key:", "rollbar_access_token:", "newrelic_api_key:", "newrelic_app_id:", "sentry_dsn:", "travis_token:", "circleci_token:", "aws_access_key:", "aws_secret_key:", "api key:", "passwd:", "pwd:", "heroku:", "slack:", "firebase:", "swagger:", "aws_secret_key:", "aws key:", "password:", "ftp password:", "jdbc:", "db:", "sql:", "secret jet:", "config:", "admin:", "pwd:", "json:", "gcp:", "htaccess:", " .env:", "ssh key:", " .git:", "access key:", "secret token:", "oauth_token:", "oauth_token_secret:", "user:", "name:", "PRIVATE", "private"
    ]

    # Search for keywords in files within the directory
    matched_files = search_keywords_in_files(directory_path, keywords)

    # Print the results grouped by keywords
    for keyword, files in matched_files.items():
        print(f"Keyword: {keyword}")
        for file in files:
            print(f"    {file}")
        print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print_ascii_art()
        print("Usage: python js-CredHunter.py <directory_path>")
        sys.exit(1)
    
    directory_path = sys.argv[1]
    if not os.path.isdir(directory_path):
        print("Error: Directory path does not exist.")
        sys.exit(1)
    
    print_ascii_art()
    main(directory_path)
