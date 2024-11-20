#Parameters
Param (
    [String] [Parameter(Mandatory=$true)] $userId,
    [bool] [parameter(Mandatory=$False)] $useMFA = $true,
    [bool] [parameter(Mandatory=$False)] $suspendUser = $true,
    [String] [Parameter(Mandatory=$False)] $logfile = ".\revoke-all-sessions.log"
)

#Imports
Import-Module .\API-Utilities.psm1 -Force
Import-Module .\Utilities.psm1 -Force
Import-Module Microsoft.Graph.Users.Actions

# Variables
$tenant_id = "" # MS tenant ID for org
$itss_app_id = "" # App ID in Azure
# Graph API scopes
$scopes = "User.ReadWrite.All,Directory.ReadWrite.All"
$ss_secret_id = "" # Secret ID in Secret Server
$okta_secret_id = "" # Secret ID in Secret Server

# Execution starts below
$start_ts = Get-Date
Set-LogFileName -filename $logfile
Write-LogMessage -message "Script started"
# Connect to Graph API
Connect-MgGraph -TenantId $tenant_id -ClientId $itss_app_id -Scopes $scopes | Out-Null
# Get session token for interactive user
$token = Get-SecretServerBearerToken -useMFA $useMFA
# Get secret for Secret Server API user
$secret = Get-SecretById -token $token -secretid $ss_secret_id
$ss_api_user = $secret.items.itemValue[1]
$ss_api_secret = $secret.items.itemValue[2]
Write-LogMessage -message "Revoking user based SS token"
Revoke-SecretServerBearerToken -token $token
# Get session token for Secret Server API user
Write-LogMessage -message "Obtaining SS token for API user"
$ss_api_token = Get-SecretServerBearerToken -ss_user $ss_api_user -ss_pw_string $ss_api_secret -useMFA $False
# Revoke Okta session
Write-LogMessage -message "Revoking Okta session for $userId"
$okta_api_key = Get-SecretById -token $ss_api_token -secretid $okta_secret_id
$user_data = Get-OktaUserData -loginName $userId -oktaApiKey $okta_api_key.items.itemValue[2]
$user_okta_id = $user_data.id
$user_login = $user_data.profile.login
Revoke-OktaSessionsByUser -oktaId $user_okta_id -oktaApiKey $okta_api_key.items.itemValue[2] | Out-Null
if ($suspendUser) {
    Write-LogMessage -message "Suspending Okta user $userId"
    Suspend-OktaUser -oktaId $user_okta_id -oktaApiKey $okta_api_key.items.itemValue[2] | Out-Null
}
Write-LogMessage -message "Revoking all M365 sign-in sessions for $userId"
$result = Revoke-MgUserSignInSession -UserId $user_login
if ($result -eq $true) {
    Write-LogMessage -message "M365 sign-in sessions revoked for $user_login"
}
# Clean up sessions
Disconnect-MgGraph | Out-Null
Revoke-SecretServerBearerToken -token $ss_api_token
$finish_ts = Get-Date
$runtime = $($finish_ts - $start_ts).TotalSeconds
Write-LogMessage -message $("Script complete in " + $runtime + " seconds.")