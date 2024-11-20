# Scripts repository
This repository is a place to stash various scripts that were created for administration and security-related tasks.  There is no overall theme to this repo and this may contain a mix of scripting languages.

## General notes
The PowerShell libraries and scripts below are designed for use with:
- Microsoft Graph API
- Okta API
- Secret Server Cloud API
- Splunk Cloud API 
- TeamDynamix API

For the Microsoft Graph API, an application needs to be created in Azure and given the appropriate permissions to the required scopes. You will also need your Microsoft tenant id.

If you do not have or use Delinea Secret Server Cloud, the scripts can modified to remove the calls to Secret Server. The flow as written is as follows:
- User authentication to Secret Server using MFA
- Retrieve a Secret Server cred for an API only user
- Create a new session token to Secret Server for the API user
- Use the API user session to access the various secrets for the APIs for Okta, Splunk, etc.
- The API user in Secret Server has permissions to the API secrets, the original account login does not.

## API-Utilities.psm1
- Library with REST API calls to various services
- You will need to update the tenant_id script variable with the identifier for your various cloud services.
- For my org, it was the same across all services. YMMV.

## Utilities.psm1
- Library for logging

## RevokeUserSessions.ps1
- Input parameter -userId is the email address / username
- The Microsoft Graph Powershell modules need to be present
    - Install-Module Microsoft.Graph.Users.Actions
- Script will revoke M365 session, revoke an Okta session, and suspend the user in Okta 
- If not using Secret Server
    - Lines 28-40: can be commented out
    - Line 41: you will need to provide Okta API key

## UnsuspendOktaUser.ps1
- Input parameter -userId is the email address / username
- Script will activate/unsuspend user in Okta
- If not using Secret Server
    - Lines 20-30: can be commented out
    - Line 31: you will need to provide Okta API key
