#Parameters
Param (
    [String] [Parameter(Mandatory=$true)] $userId,
    [bool] [parameter(Mandatory=$False)] $useMFA = $true,
    [String] [Parameter(Mandatory=$False)] $logfile = ".\unsuspend-Okta-user.log"
)

#Imports
Import-Module .\API-Utilities.psm1 -Force
Import-Module .\Utilities.psm1 -Force

# Variables
$ss_secret_id = "" # Secret ID in Secret Server
$okta_secret_id = "" # Secret ID in Secret Server

# Execution starts below
$start_ts = Get-Date
Set-LogFileName -filename $logfile
Write-LogMessage -message "Script started"
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
$okta_api_key = Get-SecretById -token $ss_api_token -secretid $okta_secret_id
# Get Okta user information
$user_data = Get-OktaUserData -loginName $userId -oktaApiKey $okta_api_key.items.itemValue[2]
$user_okta_id = $user_data.id
$user_okta_status = $user_data.status
Write-LogMessage -message "Current Okta account status for $userId is $user_okta_status"
if ($user_okta_status -eq "SUSPENDED") {
    Write-LogMessage -message "Unsuspending Okta user $userId to restore account access"
    Restore-OktaUser -oktaId $user_okta_id -oktaApiKey $okta_api_key.items.itemValue[2] | Out-Null
}
else {
    Write-LogMessage -message "No action required to unsuspend Okta user $userId"
}
# Clean up sessions
Revoke-SecretServerBearerToken -token $ss_api_token
$finish_ts = Get-Date
$runtime = $($finish_ts - $start_ts).TotalSeconds
Write-LogMessage -message $("Script complete in " + $runtime + " seconds.")