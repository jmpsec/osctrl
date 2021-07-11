##
## {{ .Project }} - Tool to quick-add Windows nodes
##
## IMPORTANT! If osquery is not installed, it will be installed.

## Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://host/path/test.ps1'))

#Requires -Version 3.0

# Force Powershell to use TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Stop as soon as there is an error
$ErrorActionPreference = "Stop"

$projectName = "{{ .Project }}"
$projectSecret = "{{ .Environment.Secret }}"
$progFiles = [System.Environment]::GetEnvironmentVariable('ProgramFiles')
$osqueryPath = (Join-Path $progFiles "osquery")
$daemonFolder = (Join-Path $osqueryPath "osqueryd")
$extensionsFolder = (Join-Path $osqueryPath "extensions")
$logFolder = (Join-Path $osqueryPath "log")
$osqueryDaemon = (Join-Path $daemonFolder "osqueryd.exe")
$secretFile = (Join-Path $osqueryPath "{{ .Project }}.secret")
$flagsFile = (Join-Path $osqueryPath "osquery.flags")
$certFile = (Join-Path $osqueryPath "{{ .Project }}.crt")
$osqueryMSI = "https://osquery-packages.s3.amazonaws.com/windows/osquery-4.7.0.2.msi"
$osqueryTempMSI = "C:\Windows\Temp\osquery-4.7.0.2.msi"
#$osqueryMSISize = 9953280
$serviceName = "osqueryd"
$serviceDescription = "osquery daemon service"
$osqueryFlags = @"
{{ .Environment.Flags }}
"@
$osqueryFlags = $osqueryFlags -replace "__SECRET_FILE__", $secretFile
$osqueryFlags = $osqueryFlags -replace "__CERT_FILE__", $certFile
$osqueryCertificate = @"
{{ .Environment.Certificate }}
"@

# Adapted from http://www.jonathanmedd.net/2014/01/testing-for-admin-privileges-in-powershell.html
function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator"
  )
}

# From https://github.com/facebook/osquery/blob/master/tools/provision/chocolatey/osquery_utils.ps1
# Helper function to add an explicit Deny-Write ACE for the Everyone group
function Set-DenyWriteAcl {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
  [OutputType('System.Boolean')]
  param(
    [string] $targetDir = '',
    [string] $action = ''
  )
  if (($action -ine 'Add') -and ($action -ine 'Remove')) {
    Write-Debug '[-] Invalid action in Set-DenyWriteAcl.'
    return $false
  }
  if ($PSCmdlet.ShouldProcess($targetDir)) {
    $acl = Get-Acl $targetDir
    $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $permType = [System.Security.AccessControl.AccessControlType]::Deny

    $worldSIDObj = New-Object System.Security.Principal.SecurityIdentifier ('S-1-1-0')
    $worldUser = $worldSIDObj.Translate([System.Security.Principal.NTAccount])
    $permission = $worldUser.Value, "write", $inheritanceFlag, $propagationFlag, $permType
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    # We only support adding or removing the ACL
    if ($action -ieq 'add') {
      $acl.SetAccessRule($accessRule)
    } else {
      $acl.RemoveAccessRule($accessRule)
    }
    Set-Acl $targetDir $acl
    return $true
  }
  return $false
}

# From https://github.com/facebook/osquery/blob/master/tools/provision/chocolatey/osquery_utils.ps1
# A helper function to set "safe" permissions for osquery binaries
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
      Try {
        $acl.RemoveAccessRule($access)
      } Catch [System.Management.Automation.MethodInvocationException] {
        if ($_.FullyQualifiedErrorId -ne 'IdentityNotMappedException') {
          Throw "Error trying to remove access ($access)"
        }
      }
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

# Helper function to add to the SYSTEM path
function Add-ToSystemPath {
  param(
    [string] $targetFolder = ''
  )

  $oldPath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
  if (-not ($oldPath -imatch [regex]::escape($targetFolder))) {
    $newPath = $oldPath
    if ($oldPath[-1] -eq ';') {
      $newPath = $newPath + $targetFolder
    } else {
      $newPath = $newPath + ';' + $targetFolder
    }
    [System.Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
  }
}

function QuickAdd-Node {
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
    #do {
    #  Start-Sleep -Seconds 2
    #  $fileSize= (Get-Item $osqueryTempMSI).Length
    #} until ($fileSize -eq $osqueryMSISize)
    Write-Host "[+] Installing osquery"
    msiexec /i $osqueryTempMSI /passive /norestart /qn
    Start-Sleep -Seconds 5
  } else {
    Write-Host "[+] osquery is installed"
  }

  # Lastly, ensure that the Deny Write ACLs have been removed before modifying
  Write-Host "[+] Setting Deny Write ACLs"
  if (Test-Path $daemonFolder) {
    Set-DenyWriteAcl $daemonFolder 'Remove'
  }
  if (Test-Path $extensionsFolder) {
    Set-DenyWriteAcl $extensionsFolder 'Remove'
  }
  Set-DenyWriteAcl $osqueryDaemon 'Remove'

  # Making sure non-privileged write access is not allowed
  Write-Host "[+] Setting $daemonFolder safe permissions"
  Set-SafePermissions $daemonFolder

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
  $projectSecret | Out-File -FilePath $secretFile -Encoding ASCII

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

  # Start osqueryd service
  if ($osquerydService) {
    if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
      Write-Debug 'Installing osquery daemon service.'
      # If the 'install' parameter is passed, we create a Windows service with
      # the flag file in the default location in \Program Files\osquery\
      # the flag file in the default location in Program Files
      $cmd = '"{0}" --flagfile="C:\Program Files\osquery\osquery.flags"' -f $osqueryDaemon

      $svcArgs = @{
        Name = $serviceName
        BinaryPathName = $cmd
        DisplayName = $serviceName
        Description = $serviceDescription
        StartupType = "Automatic"
      }
      New-Service @svcArgs

      # If the osquery.flags file doesn't exist, we create a blank one.
      if (-not (Test-Path "$targetFolder\osquery.flags")) {
        Add-Content "$targetFolder\osquery.flags" $null
      }
    }
    Start-Service $serviceName
    Write-Host "[+] '$serviceName' system service is started." -foregroundcolor Cyan
  } else {
    Write-Host "[+] '$serviceName' is not an installed system service." -foregroundcolor Yellow
    Exit 1
  }

  # Add osquery binary path to machines path for ease of use.
  Write-Host "[+] Adding osquery to path"
  Add-ToSystemPath $targetFolder

  Write-Host "Congratulations! The node has been enrolled in $projectName"
  Write-Host "REMINDER! $serviceName has been started and enabled."
}

QuickAdd-Node
