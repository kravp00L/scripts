# Module variables
New-Variable -Name tenant_id -Value "your_org" -Scope Script -Force
<#
.Synopsis
Get token for API access to Secret Server Cloud

.Description
Retrieves a bearer token from Secret Server Cloud using either a local 
application account without MFA or a domain-based user account with MFA
 enabled. Returns a string value that contains the bearer token.

.Parameter ss_user
Optional string value for username

.Parameter .ss_pw_string
Optional string value for password 

.Parameter useMFA
Boolean value to flag whether or not the account requires MDA via OTP for
authentication.

#>
Function Get-SecretServerBearerToken {
    param(
        [string] [Parameter(Mandatory=$False)] $ss_user = $null,
        [string] [Parameter(Mandatory=$False)] $ss_pw_string = $null,
        [bool] $useMFA = $false
    )
    # Get bearer session token - valid for 20 minutes by default
    Write-LogMessage -message "Getting Secret Server bearer token"
    $auth_uri = "https://$tenant_id.secretservercloud.com/oauth2/token"
    if (-not ($ss_user -and $ss_pw_string)) {
        $ss_user = Read-Host "Enter Secret Server username"
        $ss_pw = Read-Host "Enter Secret Server credential" -AsSecureString
        $ss_pw_string = (New-Object System.Management.Automation.PSCredential 'N/A', $ss_pw).GetNetworkCredential().Password
    }
    $auth_data = @{username = $ss_user; password = $ss_pw_string; grant_type = "password"}
    if ($useMFA) {
       $mfa_code = Read-Host "Enter your Duo MFA code"
       $auth_data['domain'] = $tenant_id
       $auth_data['OTP'] = $mfa_code
    }
    # Get token from Secret Server
    try {
        $response = Invoke-RestMethod $auth_uri -Method Post -Body $auth_data -ContentType "application/json"
    }
    catch {
        Write-LogMessage -message "Error trying to get Secret Server bearer token."
        Write-LogMessage -message "Error: $_"
    }
    return $response.access_token
}

<#
.Synopsis
Revokes a Secret Server Cloud bearer token.

.Description
Revokes a Secret Server Cloud bearer token.

.Parameter token
String value of the Secret Server Cloud token to be revoked

.Example
Revoke-Token -token "<SS cloud token>"
#>
Function Revoke-SecretServerBearerToken {
    param(
        [string] [Parameter(Mandatory=$true)] $token
    )
    Write-LogMessage -message "Revoking bearer token to expire current session"
    $revoke_uri = "https://$tenant_id.secretservercloud.com/api/v1/oauth-expiration"
    $auth_header = Set-SecretServerAuthHeader -token $token
    try {
        $response = Invoke-RestMethod -Method Post -Uri $revoke_uri -Headers $auth_header -ContentType "application/json"
    }
    catch {
        Write-LogMessage -message "Error trying to revoke Secret Server bearer token."
        Write-LogMessage -message "Error: $_"
    }
    finally {
        if ($response -eq $true) {
            Write-LogMessage -message "Secret Server session successfully expired"
        }
    }
}

<#
.Synopsis
Create authorization header for Secret Server Cloud API calls.

.Description
Creates an authorization header to be returned with each call to the Secret
Server cloud API. A valid bearer token is required.

.Parameter token
String containing valid bearer token issued by Secret Server Cloud

.Example
Set-SecretServerAuthHeader -token <token string>
#>
Function Set-SecretServerAuthHeader {
    param(
        [string] [Parameter(Mandatory=$true)] $token
    )
    $header = New-Object "System.collections.Generic.Dictionary[[String],[String]]"
    $header.Add("Authorization", "Bearer $token")    
    return $header
}

<#
.Synopsis
Retrieve secret from Secret Server Cloud via API.

.Description
Retrieve a secret based on the secret ID from Secret Server Cloud via API.

.Parameter token
String containing valid bearer token issued by Secret Server Cloud.

.Parameter secretid
String containing the secret ID to be retrieved from Secret Server Cloud.

.Example
Get-SecretById -token <token string> -secretid "5034"
#>
Function Get-SecretById {
    param(
        [string] [Parameter(Mandatory=$true)] $token,
        [string] [Parameter(Mandatory=$true)] $secretid
    )
    $secrets_api_uri = "https://$tenant_id.secretservercloud.com/api/v2/secrets/" + $secretid
    $auth_header = Set-SecretServerAuthHeader -token $token
    try {
        $secret = Invoke-RestMethod $secrets_api_uri -Method Get -Headers $auth_header -ContentType "application/json"
    }
    catch {
        Write-LogMessage -message "Error trying to retrieve secret ID $secretid via API."
        Write-LogMessage -message "Error: $_"
    }
    return $secret
}

<#
.Synopsis
Authenticate to Splunk Cloud and retrieve session token.

.Description
Authenticates to Splunk Cloud after prompting for username and
password. After successful authentication returns a session
token that is passed for subsequent calls to the Splunk Cloud API.

.Parameter splunk_user
Optional string containing Splunk Cloud username

.Parameter pw_string
Optional string containing Splunk Cloud password

.Example
Get-SplunkSessionToken
#>
Function Get-SplunkSessionToken {
    param(
        [string] [Parameter(Mandatory=$False)] $splunk_user = $null,
        [string] [Parameter(Mandatory=$False)] $pw_string = $null
    )
    Write-LogMessage -message "Getting Splunk session token"
    $auth_uri = "https://$tenant_id.splunkcloud.com:8089/services/auth/login"
    if (-not ($splunk_user -and $pw_string)) {
        $splunk_user = Read-Host "Enter Splunk Cloud username"
        $splunk_pw = Read-Host "Enter Splunk Cloud credential" -AsSecureString
        $pw_string = (New-Object System.Management.Automation.PSCredential 'N/A', $splunk_pw).GetNetworkCredential().Password
    }
    $auth_data = @{username = $splunk_user; password = $pw_string}
    try { 
        $response = Invoke-RestMethod -Uri $auth_uri -Method POST -Body $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to get Splunk session token."
        Write-LogMessage -message "Error message: $_"
    }
    return $response.response.sessionKey
}

<#
.Synopsis
Revokes a Secret Server Cloud bearer token.

.Description
Revokes a Secret Server Cloud bearer token.

.Parameter token
Splunk Cloud token to be revoked

.Example
Revoke-SplunkSessionToken -auth_header "JSON/hashtable header"
#>
Function Revoke-SplunkSessionToken {
    param(
        [string] [Parameter(Mandatory=$true)] $token
    )
    Write-LogMessage -message "Revoking Splunk Cloud session token to expire current session"
    # TODO: Check the URI and response, below is just placeholder copied from Secret Server
    $revoke_uri = "https://$tenant_id.splunkcloud.com:8089/services/auth/login"
    $response = Invoke-RestMethod $revoke_uri -Method Post -Headers $auth_header -ContentType "application/json"
    if ($response -eq $true) {
        Write-LogMessage -message "Splunk Cloud session successfully revoked"
    }
}

<#
.Synopsis
Create authorization header for Splunk Cloud API calls.

.Description
Creates an authorization header to be returned with each call to the Splunk
Cloud API. A valid session token is required.

.Parameter token
String containing valid bearer token issued by Splunk Cloud

.Example
Set-SplunkAuthHeader -token <token string>
#>
Function Set-SplunkAuthHeader {
    param(
        [string] [Parameter(Mandatory=$true)] $token
    )
    $splunk_auth_header = @{Authorization = ""}
    $splunk_auth_header.Authorization = "Splunk " + $token
    return $splunk_auth_header
}

<#
.Synopsis
Authenticate to Team Dynamix and retrieve admin session token.

.Description
Authenticates to the Team Dynamix Admin after retrieving the BEID and 
web services key from Secret Server. After successful authentication 
returns a session token that is passed for subsequent calls to the TDX API.

.Parameter beid
String containing the GUID of the login BEID 

.Parameter beid
String containing the GUID of the TDX web services key for the login BEID

.Example
TdxAdminSessionToken -beid <BEID GUID> -web_svcs_key <key GUID>
#>
Function Get-TdxAdminSessionToken {
    param(
        [string] [Parameter(Mandatory=$true)] $beid,
        [string] [Parameter(Mandatory=$true)] $web_svcs_key
    )
    Write-LogMessage -message "Getting TDX API Admin session token"
    $auth_uri = "https://$tenant_id.teamdynamix.com/TDWebApi/api/auth/loginadmin"
    $auth_data = "{'BEID':'$beid', 'WebServicesKey':'$web_svcs_key'}"
    try {
        $response = Invoke-RestMethod -Method POST -ContentType "application/json; charset=utf-8" -Uri $auth_uri -Body $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to get TDX session token."
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}

<#
.Synopsis
Authenticate to Team Dynamix and retrieve session token.

.Description
Authenticates to the Team Dynamix API after prompting for username and
password. After successful authentication returns a session token that
is passed for subsequent calls to the TDX API.

.Parameter tdx_user
String containing valid username for TDX with API access

.Parameter tdx_pw_string
String containing valid API key associated with username 

.Example
Get-TdxSessionToken
#>
Function Get-TdxSessionToken {
    param(
        [string] [Parameter(Mandatory=$False)] $tdx_user = $null,
        [string] [Parameter(Mandatory=$False)] $tdx_pw_string = $null
    )
    Write-LogMessage -message "Getting TDX API session token"
    $auth_uri = "https://$tenant_id.teamdynamix.com/TDWebApi/api/auth/login"
    if (-not ($tdx_user -and $tdx_pw_string)) {
        $tdx_user = Read-Host "Enter TDX API username"
        $tdx_pw = Read-Host "Enter TDX API credential" -AsSecureString
        $tdx_pw_string = (New-Object System.Management.Automation.PSCredential 'N/A', $tdx_pw).GetNetworkCredential().Password
    }
    $auth_data = "{'username':'$tdx_user', 'password':'$tdx_pw_string'}"
    try {
        $response = Invoke-RestMethod -Method POST -ContentType "application/json; charset=utf-8" -Uri $auth_uri -Body $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to get TDX session token."
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}

<#
.Synopsis
Authenticate to Team Dynamix sandbox API and retrieve session token.

.Description
Authenticates to the Team Dynamix sandbox API. After successful
authentication returns a session token that is passed for subsequent
calls to the TDX API.

.Parameter tdx_user
String containing valid username for TDX with API access

.Parameter tdx_pw_string
String containing valid API key associated with username 

.Example
Get-TdxSandboxSessionToken
#>
Function Get-TdxSandboxSessionToken {
    param(
        [string] [Parameter(Mandatory=$False)] $tdx_user = $null,
        [string] [Parameter(Mandatory=$False)] $tdx_pw_string = $null
    )
    Write-LogMessage -message "Getting TDX API session token"
    $auth_uri = "https://$tenant_id.teamdynamix.com/SBTDWebApi/api/auth/login"
    if (-not ($tdx_user -and $tdx_pw_string)) {
        $tdx_user = Read-Host "Enter TDX API username"
        $tdx_pw = Read-Host "Enter TDX API credential" -AsSecureString
        $tdx_pw_string = (New-Object System.Management.Automation.PSCredential 'N/A', $tdx_pw).GetNetworkCredential().Password
    }
    $auth_data = "{'username':'$tdx_user', 'password':'$tdx_pw_string'}"
    try {
        $response = Invoke-RestMethod -Method POST -ContentType "application/json; charset=utf-8" -Uri $auth_uri -Body $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to get TDX session token."
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}

<#
.Synopsis
Retrieve people record from TDX

.Description
Using the Team Dynamix API, retrieve information about a person
from the system.

.Parameter token
String containing valid session token issued by TDX

.Parameter uid
String containing valid user ID for TDX people record

.Example
Get-TdxPersonById -token <TDX token> -uid "d11124c8-82bf-eb11-a969-000d3a1506a4"
#>
Function Get-TdxPersonById {
    param(
        [string] [Parameter(Mandatory=$true)] $token,
        [string] [Parameter(Mandatory=$true)] $uid
    )
    Write-LogMessage -message "Getting TDX record for ID $uid"
    $auth_data = Set-TdxAuthHeader -token $token
    $people_uri = "https://$tenant_id.teamdynamix.com/TDWebApi/api/people/$uid"
    try {
        $response = Invoke-RestMethod -Method Get -ContentType "application/json; charset=utf-8" -Uri $people_uri -Headers $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to get TDX info for UID $uid."
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}

<#
.Synopsis
Retrieve ticket record from TDX

.Description
Using the Team Dynamix API, retrieve information about a ticket
from the system.
https://solutions.teamdynamix.com/TDWebApi/Home/section/Tickets

.Parameter token
String containing valid session token issued by TDX

.Parameter ticketid
String containing valid ticket number

.Example
Get-TdxTicketById -token <TDX token> -ticketid "444299"
#>
Function Get-TdxTicketById {
    param(
        [string] [Parameter(Mandatory=$true)] $token,
        [string] [Parameter(Mandatory=$true)] $ticketid
    )
    Write-LogMessage -message "Getting TDX record for ticket $ticketid"
    $auth_data = Set-TdxAuthHeader -token $token
    $ticket_url = "https://$tenant_id.teamdynamix.com/TDWebApi/api/30/tickets/$ticketid"
    try {
        $response = Invoke-RestMethod -Method Get -ContentType "application/json; charset=utf-8" -Uri $ticket_url -Headers $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to get TDX info for ticket $ticketid."
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}

<#
.Synopsis
Create a new ticket in TDX

.Description
Using the Team Dynamix API, create a new ticket
https://solutions.teamdynamix.com/TDWebApi/Home/section/Tickets

.Parameter token
String containing valid session token issued by TDX

.Parameter ticketid
String containing valid user login / email(?)

.Example
New-TdxTicket -token <TDX token> -userid zbikowsm
#>
Function New-TdxTicket {
    param(
        [string] [Parameter(Mandatory=$true)] $token,
        [string] [Parameter(Mandatory=$true)] $userid,
        [string] [Parameter(Mandatory=$false)] $ticket_title,
        [string] [Parameter(Mandatory=$false)] $ticket_description
    )
    Write-LogMessage -message "Creating new TDX ticket for user $userid"
    $auth_data = Set-TdxAuthHeader -token $token
    $ticket_url = "https://$tenant_id.teamdynamix.com/TDWebApi/api/30/tickets/$ticketid"
    "https://solutions.teamdynamix.com/TDWebApi/api/{appId}/tickets?EnableNotifyReviewer={EnableNotifyReviewer}&NotifyRequestor={NotifyRequestor}&NotifyResponsible={NotifyResponsible}&AllowRequestorCreation={AllowRequestorCreation}&applyDefaults={applyDefaults}"
    # Required fields below
    $ticket_data = @{
        TypeID ="String value of ticket type";
        Title = $ticket_title;
        Description = $ticket_description;
        AccountId = 1;
        StatusId = 2;
        PriorityID = 3
        RequestorUid="string guid value of TDX requestor id"
    }

    try {
        $response = Invoke-RestMethod -Method Post -ContentType "application/json; charset=utf-8" -Uri $ticket_url -Headers $auth_data -Body $ticket_data
    }
    catch {
        Write-LogMessage -message "Error trying to create new TDX ticket."
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}

<#
.Synopsis
Retrieve KB article from TDX

.Description
Using the Team Dynamix admin API, retrieve a KB article 
from the system.

.Parameter token
String containing valid session token issued by TDX

.Parameter kbid
String containing valid KB article number

.Example
Get-TdxKbArticleById -token <TDX token> -kbid "207"
#>
Function Get-TdxKbArticleById {
    param(
        [string] [Parameter(Mandatory=$true)] $token,
        [string] [Parameter(Mandatory=$true)] $kbid
    )
    Write-LogMessage -message "Getting TDX KB article $kbid"
    $auth_data = Set-TdxAuthHeader -token $token
    $kb_url = "https://$tenant_id.teamdynamix.com/TDWebApi/api/31/knowledgebase/$kbid"
    try {
        $response = Invoke-RestMethod -Method Get -ContentType "application/json; charset=utf-8" -Uri $kb_url -Headers $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to get TDX KB article $kbid."
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}


<#
.Synopsis
Create authorization header for TDX API calls.

.Description
Creates an authorization header to be returned with each call to the TDX
API. A valid TDX bearer token is required.

.Parameter token
String containing valid bearer token issued by TDX

.Example
Set-TdxAuthHeader -token <token string>
#>
Function Set-TdxAuthHeader {
    param(
        [string] [Parameter(Mandatory=$true)] $token
    )
    $tdx_auth_header = @{Authorization = ""}
    $tdx_auth_header.Authorization = "Bearer " + $token
    return $tdx_auth_header
}

<#
.Synopsis
Retrieve the Okta information for a user.

.Description
Retrieve the Okta information for a user. The Okta ID is needed for actions
on the user and user sessions.
https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/getUser

.Parameter loginName
String value of the login name for the account

.Parameter oktaApiKey
String value of Okta API key

.Example
Get-OktaUserData -loginName ZBIKOWSM -oktaApiKey <API key>
#>
Function Get-OktaUserData {
    param(
        [string] $loginName,
        [string] $oktaApiKey
    )
    $auth_data = Set-OktaAuthHeader -key $oktaApiKey
    $user_url = "https://$tenant_id.okta.com/api/v1/users/$loginName"
    try {
        $response = Invoke-RestMethod -Method Get -ContentType "application/json; okta-response=omitCredentials,omitCredentialsLinks" -Uri $user_url -Headers $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to retrieve Okta user information for $loginName"
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}

<#
.Synopsis
Revokes all Okta sessions for a user.

.Description
Revokes all Okta sessions for a user.
https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserSessions/#tag/UserSessions/operation/revokeUserSessions

.Parameter oktaId
String value of the Okta ID (not login name) for the account

.Parameter oktaApiKey
String value of the Okta API key

.Example
Revoke-OktaSessionsByUser -oktaId "00u1ef6spxVIK1CzS697" -oktaApiKey <API key>
#>
Function Revoke-OktaSessionsByUser {
    param(
        [string] $oktaId,
        [string] $oktaApiKey
    )
    $auth_data = Set-OktaAuthHeader -key $oktaApiKey
    $revoke_url = "https://$tenant_id.okta.com/api/v1/users/$oktaId/sessions?oauthTokens=false"
    try {
        # returns a HTTP 204 No Content if successful
        $response = Invoke-RestMethod -Method Delete -Uri $revoke_url -Headers $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to revoke Okta sessions for $oktaId."
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}

<#
.Synopsis
Suspend an Okta user

.Description
Suspend a user using their Okta ID. Suspended users can't sign in to Okta.
They can only be unsuspended or deactivated.
https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserLifecycle/#tag/UserLifecycle/operation/suspendUser

.Parameter oktaId
String value of the Okta ID (not login name) for the account

.Parameter oktaApiKey
String value of Okta API key

.Example
Suspend-OktaUser -oktaId "00u1ef6spxVIK1CzS697" -oktaApiKey <API key>
#>
Function Suspend-OktaUser {
    param(
        [string] $oktaId,
        [string] $oktaApiKey
    )
    $auth_data = Set-OktaAuthHeader -key $oktaApiKey
    $suspend_user_url = "https://$tenant_id.okta.com/api/v1/users/$oktaId/lifecycle/suspend"
    try {
        $response = Invoke-RestMethod -Method Post -ContentType "application/json;" -Uri $suspend_user_url -Headers $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to suspend Okta ID $oktaId"
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}

<#
.Synopsis
Unsuspend an Okta user

.Description
Unsuspend a user using their Okta ID. Suspended users can't sign in to Okta.
https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserLifecycle/#tag/UserLifecycle/operation/unsuspendUser

.Parameter oktaId
String value of the Okta ID (not login name) for the account

.Parameter oktaApiKey
String value of Okta API key

.Example
Restore-OktaUser -oktaId "00u1ef6spxVIK1CzS697" -oktaApiKey <API key>
#>
Function Restore-OktaUser {
    param(
        [string] $oktaId,
        [string] $oktaApiKey
    )
    $auth_data = Set-OktaAuthHeader -key $oktaApiKey
    $suspend_user_url = "https://$tenant_id.okta.com/api/v1/users/$oktaId/lifecycle/unsuspend"
    try {
        $response = Invoke-RestMethod -Method Post -ContentType "application/json;" -Uri $suspend_user_url -Headers $auth_data
    }
    catch {
        Write-LogMessage -message "Error trying to unsuspend Okta ID $oktaId"
        Write-LogMessage -message "Error message: $_"
    }
    return $response
}

<#
.Synopsis
Create authorization header for Okta API calls.

.Description
Creates an authorization header to be returned with each call to the Okta
Cloud API.

.Parameter key
String containing valid API key 

.Example
Set-OktaAuthHeader -key <token string>
#>
Function Set-OktaAuthHeader {
    param(
        [string] $key
    )
    $okta_auth_header = @{Authorization = ""}
    $okta_auth_header.Authorization = "SSWS $key"
    return $okta_auth_header
}

Export-ModuleMember -Function *