#requires -version 2

## Tool to add Windows nodes into osctrl
##
## IMPORTANT! If osquery is not installed, it will be installed.

## Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://host/path/test.ps1'))

# Force Powershell to use TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Stop as soon as there is an error
$ErrorActionPreference = "Stop"

$projectName = "{{ .Project }}"
$osctrlTLSHost = "{{ .Context.Hostname }}"
$osctrlSecret = "{{ .Context.Secret }}"
$osqueryPath = ([System.IO.Path]::Combine('C:\', 'ProgramData', 'osquery'))
$osqueryDaemonPath = (Join-Path $osqueryPath "osqueryd")
$osqueryDaemon = (Join-Path $osqueryDaemonPath "osqueryd.exe")
$secretFile = (Join-Path $osqueryPath "osquery.secret")
$flagsFile = (Join-Path $osqueryPath "osquery.flags")
$certFile = (Join-Path $osqueryPath "{{ .Project }}.crt")
$osqueryMSI = "https://osquery-packages.s3.amazonaws.com/windows/osquery-3.3.1.msi"
$osqueryTempMSI = "C:\Windows\Temp\osquery-3.3.1.msi"
$osqueryMSISize = 9953280
$serviceName = "osqueryd"
$serviceDescription = "osquery daemon service"
$osqueryFlags = @"
--host_identifier=uuid
--force=true
--utc=true
--enroll_secret_path=$secretFile
--enroll_tls_endpoint=/{{ .Context.Name }}/{{ .Path.EnrollPath }}
--config_plugin=tls
--config_tls_endpoint=/{{ .Context.Name }}/{{ .Path.ConfigPath }}
--config_tls_refresh=10
--logger_plugin=tls
--logger_tls_compress=true
--logger_tls_endpoint=/{{ .Context.Name }}/{{ .Path.LogPath }}
--logger_tls_period=10
--disable_distributed=false
--distributed_interval=10
--distributed_plugin=tls
--distributed_tls_max_attempts=3
--distributed_tls_read_endpoint=/{{ .Context.Name }}/{{ .Path.QueryReadPath }}
--distributed_tls_write_endpoint=/{{ .Context.Name }}/{{ .Path.QueryWritePath }}
--tls_dump=true
--tls_hostname=$osctrlTLSHost
--tls_server_certs=$certFile
"@
$osqueryCertificate = @"
{{ .Context.Certificate }}
"@

# Adapted from http://www.jonathanmedd.net/2014/01/testing-for-admin-privileges-in-powershell.html
function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator"
  )
}

# A helper function to set "safe" permissions for osquery binaries
# From https://github.com/facebook/osquery/blob/master/tools/provision/chocolatey/osquery_utils.ps1
function Set-SafePermissions {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  [OutputType('System.Boolean')]
  param(
    [string] $target = ''
  )
  if ($PSCmdlet.ShouldProcess($target)) {
    $acl = Get-Acl $target

    # First, to ensure success, we remove the entirety of the ACL
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($access in $acl.Access) {
      $acl.RemoveAccessRule($access)
    }
    Set-Acl $target $acl

    $acl = Get-Acl $target
    $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $permType = [System.Security.AccessControl.AccessControlType]::Allow

    # "Safe" permissions in osquery entail the containing folder and binary both
    # are owned by the Administrators group, as well as no account has Write
    # permissions except for the Administrators group and SYSTEM account
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $systemUser = $systemSid.Translate([System.Security.Principal.NTAccount])

    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $adminsGroup = $adminsSid.Translate([System.Security.Principal.NTAccount])

    $usersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $usersGroup = $usersSid.Translate([System.Security.Principal.NTAccount])

    $permGroups = @($systemUser, $adminsGroup, $usersGroup)
    foreach ($accnt in $permGroups) {
      $grantedPerm = ''
      if ($accnt -eq $usersGroup) {
        $grantedPerm = 'ReadAndExecute'
      } else {
        $grantedPerm = 'FullControl'
      }
      $permission = $accnt.Value, $grantedPerm, $inheritanceFlag, $propagationFlag, $permType
      $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
      $acl.SetAccessRule($accessRule)
    }
    $acl.SetOwner($adminsGroup)
    Set-Acl $target $acl

    # Finally set the Administrators group as the owner for all items
    $items = Get-ChildItem -Recurse -Path $target
    foreach ($item in $items) {
      $acl = Get-Acl -Path $item.FullName
      $acl.SetOwner($adminsGroup)
      Set-Acl $item.FullName $acl
    }

    return $true
  }
  return $false
}

function Osctrl-Node
{
  # Make sure we are admin
  if (-not (Test-IsAdmin)) {
    Write-Host "[!] Please run this script with Admin privileges!" -foregroundcolor Red
    Exit -1
  }
  # Verify osquery
  if (!(Test-Path $osqueryDaemon)) {
    Write-Host "[+] $projectName needs osquery"
    Write-Host "[+] Downloading osquery"
    (New-Object System.Net.WebClient).DownloadFile($osqueryMSI, $osqueryTempMSI)
    do {
      Start-Sleep -Seconds 2
      $fileSize= (Get-Item $osqueryTempMSI).Length
    } until ($fileSize -eq $osqueryMSISize)
    Write-Host "[+] Installing osquery"
    msiexec /i $osqueryTempMSI /passive /norestart /qn
    Start-Sleep -Seconds 5
  } else {
    Write-Host "[+] osquery is installed"
  }

  # Making sure non-privileged write access is not allowed
  Write-Host "[+] Setting osquery safe permissions"
  Set-SafePermissions $osqueryDaemonPath

  # Stop osquery service
  $osquerydService = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
  if ($osquerydService) {
    Stop-Service $serviceName
    Write-Host "[+] '$serviceName' system service is stopped." -foregroundcolor Cyan
    Start-Sleep -s 5
    $osquerydService.Delete()
    Write-Host "System service '$serviceName' uninstalled." -foregroundcolor Cyan
  }

  # Prepare secret
  Write-Host "[+] Preparing osquery secret"
  if (!(Test-Path $secretFile)) {
    New-Item -ItemType "file" -Path $secretFile
  }
  $osctrlSecret | Out-File -FilePath $secretFile -Encoding ASCII

  # Prepare flags
  Write-Host "[+] Preparing osquery flags"
  if (!(Test-Path $flagsFile)) {
    New-Item -ItemType "file" -Path $flagsFile
  }
  $osqueryFlags | Out-File -FilePath $flagsFile -Encoding ASCII

  # Prepare cert
  Write-Host "[+] Preparing osquery certificate"
  if (!(Test-Path $certFile)) {
    New-Item -ItemType "file" -Path $certFile
  }
  $osqueryCertificate | Out-File -FilePath $certFile -Encoding ASCII

  # Start osquery
  if ($osquerydService) {
    New-Service -BinaryPathName "$osqueryDaemon --flagfile=$flagsFile" `
                -Name $serviceName `
                -DisplayName $serviceName `
                -Description $serviceDescription `
                -StartupType Automatic
    Start-Service $serviceName
    Write-Host "[+] '$serviceName' system service is started." -foregroundcolor Cyan
  } else {
    Write-Host "[+] '$serviceName' is not an installed system service." -foregroundcolor Yellow
    Exit 1
  }

  Write-Host "Congratulations! The node has been enrolled in $projectName"
  Write-Host "IMPORTANT! $serviceName has been started and enabled."
}

Osctrl-Node