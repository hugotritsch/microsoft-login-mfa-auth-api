import re
import os
import json
import pyotp
import requests

from typing import Dict, Union, Optional
from bs4 import BeautifulSoup
from fake_useragent import UserAgent


def get_config(response_body: str) -> Dict[str, Union[str, int]]:
    """
    Extracts configuration settings from the HTML response's <script> tag containing $Config.

    Args:
        response_body (str): HTML response as a string.

    Returns:
        Dict[str, Union[str, int]]: Parsed configuration as a dictionary, or an empty dict if not found.
    """
    soup = BeautifulSoup(response_body, 'html.parser')
    script_content = soup.find('script', string=re.compile(r'\$Config'))
    if not script_content:
        print("Config script not found.")
        return {}

    config_match = re.search(r'\$Config\s*=\s*({.*?});', script_content.string, re.DOTALL)
    if config_match:
        try:
            return json.loads(config_match.group(1))
        except json.JSONDecodeError as e:
            print(f"JSON decoding error: {e}")
    else:
        print("Config not found in script.")
    return {}


def initialize_device_auth(client_id: str, scope: str) -> requests.Response:
    """
    Initiates device authorization by sending a POST request to the device authorization endpoint.

    Args:
        client_id (str): The Application (client) ID.
        scope (str): Scope of the requested access.

    Returns:
        requests.Response: Response object containing the device authorization details.
    """
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
    payload = {"client_id": client_id, "scope": scope}
    response = session.post(url, data=payload)
    return response


def post_device_auth(user_code: str, canary: Optional[str] = None, params: Optional[Dict[str, str]] = None) -> requests.Response:
    """
    Sends the device authentication code to continue the authentication process.

    Args:
        user_code (str): User code received from the device authorization response.
        canary (Optional[str]): Canary token used for the session.
        params (Optional[Dict[str, str]]): Additional parameters for the request.

    Returns:
        requests.Response: Response object from the server.
    """
    url = "https://login.microsoftonline.com/common/oauth2/deviceauth"
    payload = {
        'otc': user_code,
        'canary': canary
    }
    response = session.post(url, data=payload, params=params)
    return response


def login(email_address: str, password: str, canary: str, contex: str, flow_token: str) -> requests.Response:
    """
    Logs in the user with provided credentials and session data.

    Args:
        email_address (str): The user's email address.
        password (str): The user's password.
        canary (str): Canary token for the session.
        contex (str): Context ID for the session.
        flow_token (str): Flow token for authentication.

    Returns:
        requests.Response: Response object containing login result.
    """
    url = "https://login.microsoftonline.com/common/login"
    payload = {
        "login": email_address,
        "loginfmt": email_address,
        "passwd": password,
        "canary": canary,
        "ctx": contex,
        "flowtoken": flow_token
    }
    response = session.post(url, data=payload)
    return response


def begin_multi_factor_auth(user_agent: str, client_request_id: str, auth_method_id: str, api_canary: str, contex: str, flow_token: str,
               hpgact: int, hpgid: int) -> requests.Response:
    """
    Initiates an authentication method for MFA (Multi-Factor Authentication).

    Args:
        user_agent (str): The user agent for the request headers.
        client_request_id (str): Unique request ID for tracking.
        auth_method_id (str): The method of authentication (e.g., SMS, phone app).
        api_canary (str): Canary token for the session.
        contex (str): Context ID for the session.
        flow_token (str): Flow token for authentication.
        hpgact (int): HPGACT parameter for tracking.
        hpgid (int): HPGID parameter for tracking.

    Returns:
        requests.Response: Response from the BeginAuth endpoint.
    """
    url = "https://login.microsoftonline.com/common/SAS/BeginAuth"
    headers = {
        "User-Agent": user_agent,
        "canary": api_canary,
        "client-request-id": client_request_id,
        "hpgact": str(hpgact),
        "hpgid": str(hpgid)
    }
    
    payload = {
        "AuthMethodId": auth_method_id,
        "Method": "BeginAuth",
        "ctx": contex,
        "flowToken": flow_token
    }
    response = session.post(url, headers=headers, json=payload)
    return response


def end_multi_factor_auth(user_agent: str, client_request_id: str, auth_method_id: str, api_canary: str, contex: str, flow_token: str, hpgact: int, hpgid: int, 
             session_id: str, additional_auth_data: Optional[str] = None) -> requests.Response:
    """
    Finalizes the MFA process by sending the user's authentication code.

    Args:
        user_agent (str): The user agent for the request headers.
        client_request_id (str): Unique request ID for tracking.
        auth_method_id (str): The method of authentication.
        api_canary (str): Canary token for the session.
        contex (str): Context ID for the session.
        flow_token (str): Flow token for authentication.
        hpgact (int): HPGACT parameter for tracking.
        hpgid (int): HPGID parameter for tracking.
        session_id (str): Session ID of the MFA attempt.
        additional_auth_data (Optional[str]): Additional data for authentication, e.g., TOTP code, SMS code,
        authenticator app or phone call.

    Returns:
        requests.Response: Response from the EndAuth endpoint.
    """
    url = "https://login.microsoftonline.com/common/SAS/EndAuth"
    headers = {
        "User-Agent": user_agent,
        "Accept": "application/json",
        "canary": api_canary,
        "client-request-id": client_request_id,
        "hpgact": str(hpgact),
        "hpgid": str(hpgid)
    }
    
    payload = {
        "AuthMethodId": auth_method_id,
        "Method": "EndAuth",
        "SessionId": session_id,
        "ctx": contex,
        "flowToken": flow_token,
        "AdditionalAuthData": additional_auth_data,
        "PollCount": 1
    }
    return session.post(url, headers=headers, json=payload)


def app_verification(canary: str, contex: str, flow_token: str) -> requests.Response:
    """
    Verifies the authentication using app verification method.

    Args:
        canary (str): Canary token for the session.
        contex (str): Context ID for the session.
        flow_token (str): Flow token for authentication.

    Returns:
        requests.Response: Response object from the app verification endpoint.
    """
    url = "https://login.microsoftonline.com/appverify"
    payload = {
        "ContinueAuth": "true",
        "ctx": contex,
        "flowToken": flow_token,
        "canary": canary
    }
    return session.post(url, data=payload)


def get_access_token(client_id: str, device_code: str) -> requests.Response:
    """
    Exchanges the device code for an OAuth2 access token.

    Args:
        client_id (str): The Application (client) ID.
        device_code (str): Device code obtained from the initial device authorization.

    Returns:
        requests.Response: Response containing the access token.
    """
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    payload = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id': client_id,
        'device_code': device_code
    }
    response = requests.post(url, data=payload)
    return response


email_address = os.environ.get("EMAIL_ADDRESS")
password = os.environ.get("PASSWORD")
client_id = os.environ.get("CLIENT_ID")
totp_secret_key = os.environ.get("TOTP_SECRET_KEY")

# Select the scope of the Microsoft resource to which you wish to connect
scope = "https://management.azure.com/.default"

# Select a MFA authentication type
#auth_method_id = "OneWaySMS"
#auth_method_id = "PhoneAppNotification"
#auth_method_id = "TwoWayVoiceMobile"
auth_method_id = "PhoneAppOTP"

session = requests.Session()

# Initialize Device Authentication
initialize_device_auth_response = initialize_device_auth(client_id, scope)
device_code = initialize_device_auth_response.json().get("device_code")
user_code = initialize_device_auth_response.json().get("user_code")

# Send the Device Authentication Code
post_device_auth_response = post_device_auth(user_code)
device_auth_config = get_config(post_device_auth_response.text)
canary = device_auth_config.get("canary")

# Send the Device Authentication Code SSO Reload
post_device_auth_sso_reload_response = post_device_auth(user_code, canary, params={"sso_reload": "true"})
device_auth_config_sso_reload = get_config(post_device_auth_sso_reload_response.text)
canary, contex, flow_token = device_auth_config_sso_reload.get("canary"), device_auth_config_sso_reload.get("sCtx"), device_auth_config_sso_reload.get("sFT")

# Login
login_response = login(email_address, password, canary, contex, flow_token)
login_config = get_config(login_response.text)
client_request_id, api_canary, contex, flow_token, hpgact, hpgid = login_config.get("correlationId"), login_config.get("apiCanary"), login_config.get("sCtx"), login_config.get("sFT"), login_config.get("hpgact"), login_config.get("hpgid")

# Trigger Multi-Factor Authentication
ua = UserAgent()

## Begin multi-factor authentication
begin_multi_factor_auth_response = begin_multi_factor_auth(ua.chrome, client_request_id, auth_method_id, api_canary, contex, flow_token, hpgact, hpgid)
begin_multi_factor_auth_config = json.loads(begin_multi_factor_auth_response.text)
session_id, flow_token, client_request_id, contex = begin_multi_factor_auth_config.get("SessionId"), begin_multi_factor_auth_config.get("FlowToken"), begin_multi_factor_auth_config.get("CorrelationId"), begin_multi_factor_auth_config.get("Ctx")

## Complete Multi-Factor Authentication
totp = pyotp.TOTP(totp_secret_key)
totp_code = totp.now()
end_multi_factor_auth_response = end_multi_factor_auth(ua.chrome, client_request_id, auth_method_id, api_canary, contex, flow_token, hpgact, hpgid, session_id, additional_auth_data=totp_code)
end_multi_factor_auth_config = json.loads(end_multi_factor_auth_response.text)
contex, flow_token = end_multi_factor_auth_config.get("Ctx"), end_multi_factor_auth_config.get("FlowToken")

# Application verification
app_verification_response = app_verification(canary, contex, flow_token)

# Get access token
access_token_response = get_access_token(client_id, device_code)
print(access_token_response.text)
