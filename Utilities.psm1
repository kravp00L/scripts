# Module variables
New-Variable -Name log_file -Value "logfile.log" -Scope Script -Force

<#
.Synopsis
Log file location

.Description
Define the location of the log file

.Parameter log_file
String with filename or path and filename of log file.

.Example
Set-LogFileName -filename "logfile.log"
#>
Function Set-LogFileName {
    param (
        [string] $filename
    )
    $Script:log_file = $filename
}

<#
.Synopsis
Log file location

.Description
Get the location of the log file

.Example
Get-LogFileName
#>
Function Get-LogFileName {
    return $Script:log_file
}

<#
.Synopsis
Log messages to screen and file.

.Description
Writes a message to the screen and to the specified log file.

.Parameter logfile
String with filename or path and filename of log file.

.Parameter message
String with message to be displayed and recorded to the log file.

.Example
Write-LogMessage -logfile "my_logfile.log" -Message "Event captured and logged"
#>
Function Write-LogMessage {
param(
    [string] $message
)
    $timestamp = Get-Date -format "yyyy-MM-dd HH:mm:ss.fff"
    Write-Host $timestamp $message
    Write-Output "$timestamp $message" | Out-File $Script:log_file ascii -Append
}
Export-ModuleMember -Function *