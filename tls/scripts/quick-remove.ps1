##
## {{ .Project }} - Tool to quick-remove Windows nodes
##
## IMPORTANT! osquery will not be removed.

## Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://host/path/test.ps1'))

#Requires -Version 3.0

# Force Powershell to use TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Stop as soon as there is an error
$ErrorActionPreference = "Stop"

$projectName = "{{ .Project }}"
$osqueryPath = ([System.IO.Path]::Combine('C:\', 'ProgramData', 'osquery'))
$osqueryDaemonPath = (Join-Path $osqueryPath "osqueryd")
$osqueryDaemon = (Join-Path $osqueryDaemonPath "osqueryd.exe")
$secretFile = (Join-Path $osqueryPath "{{ .Project }}.secret")
$flagsFile = (Join-Path $osqueryPath "osquery.flags")
$certFile = (Join-Path $osqueryPath "{{ .Project }}.crt")
$serviceName = "osqueryd"

# Adapted from http://www.jonathanmedd.net/2014/01/testing-for-admin-privileges-in-powershell.html
function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator"
  )
}

function QuickRemove-Node
{
  # Make sure we are admin
  if (-not (Test-IsAdmin)) {
    Write-Host "[!] Please run this script with Admin privileges!" -foregroundcolor Red
    Exit -1
  }

  # Stop osquery service
  $osquerydService = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
  if ($osquerydService) {
    Stop-Service $serviceName
    Write-Host "[+] '$serviceName' system service is stopped." -foregroundcolor Cyan
    Start-Sleep -s 5
    $osquerydService.Delete()
    Write-Host "System service '$serviceName' uninstalled." -foregroundcolor Cyan

    # If we find zombie processes, make sure they are terminated
    $proc = Get-Process | Where-Object { $_.ProcessName -eq 'osqueryd' }
    if ($null -ne $proc) {
      Stop-Process -Force $proc -ErrorAction SilentlyContinue
    }
  }

  # Prepare secret
  Write-Host "[+] Removing osquery secret"
  if (Test-Path $secretFile) {
    Remove-Item -ItemType "file" -Path $secretFile
  }

  # Prepare flags
  Write-Host "[+] Removing osquery flags"
  if (Test-Path $flagsFile) {
    Remove-Item -ItemType "file" -Path $flagsFile
  }

  # Prepare cert
  Write-Host "[+] Removing osquery certificate"
  if (Test-Path $certFile) {
    Remove-Item -ItemType "file" -Path $certFile
  }

  Write-Host "Congratulations! The node has been removed from $projectName"
  Write-Host "WARNING! $serviceName has been stopped and disabled."
}

QuickRemove-Node
