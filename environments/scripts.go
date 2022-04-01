package environments

// QuickAddScriptShell to keep the raw template for the quick add shell script
const QuickAddScriptShell = `
#!/bin/sh
#
# {{ .Project }} - Tool to quick-add OSX/Linux nodes
#
# IMPORTANT! If osquery is not installed, it will be installed.

_PROJECT="{{ .Project }}"
_SECRET="{{ .Environment.Secret }}"

_SECRET_LINUX=/etc/osquery/${_PROJECT}.secret
_FLAGS_LINUX=/etc/osquery/osquery.flags
_CERT_LINUX=/etc/osquery/certs/${_PROJECT}.crt

_SECRET_OSX=/private/var/osquery/${_PROJECT}.secret
_FLAGS_OSX=/private/var/osquery/osquery.flags
_CERT_OSX=/private/var/osquery/certs/${_PROJECT}.crt
_PLIST_OSX=/Library/LaunchDaemons/io.osquery.agent.plist
_OSQUERY_PLIST=/private/var/osquery/io.osquery.agent.plist

_SECRET_FREEBSD=/usr/local/etc/${_PROJECT}.secret
_FLAGS_FREEBSD=/usr/local/etc/osquery.flags
_CERT_FREEBSD=/usr/local/etc/certs/${_PROJECT}.crt

_DEB_ARCH=$(dpkg --print-architecture)

_OSQUERY_VER="5.2.2"
_OSQUERY_PKG="https://osquery-packages.s3.amazonaws.com/darwin/osquery-$_OSQUERY_VER.pkg"
_OSQUERY_DEB="https://osquery-packages.s3.amazonaws.com/deb/osquery_$_OSQUERY_VER-1.linux_$_DEB_ARCH.deb"
_OSQUERY_RPM="https://osquery-packages.s3.amazonaws.com/rpm/osquery-$_OSQUERY_VER-1.linux.x86_64.rpm"

_OSQUERY_SERVICE_LINUX="osqueryd"
_OSQUERY_SERVICE_OSX="io.osquery.agent"
_OSQUERY_SERVICE_FREEBSD="osqueryd"

_SECRET_FILE=""
_FLAGS=""
_CERT=""
_SERVICE=""

fail() {
  echo "[!] $1"
  exit 1
}

log() {
  echo "[+] $1"
}

installOsquery() {
  log "Installing osquery for $OS"
  if [ "$OS" = "linux" ]; then
    log "Installing osquery in Linux"
    distro=$(/usr/bin/rpm -q -f /usr/bin/rpm >/dev/null 2>&1)
    if [ "$?" = "0" ]; then
      log "RPM based system detected"
      _RPM="$(echo $_OSQUERY_RPM | cut -d"/" -f5)"
      sudo curl -# "$_OSQUERY_RPM" -o "/tmp/$_RPM"
      sudo rpm -ivh "/tmp/$_RPM"
    else
      log "DEB based system detected"
      _DEB="$(echo $_OSQUERY_DEB | cut -d"/" -f5)"
      sudo curl -# "$_OSQUERY_DEB" -o "/tmp/$_DEB"
      sudo dpkg -i "/tmp/$_DEB"
    fi
  fi
  if [ "$OS" = "darwin" ]; then
    log "Installing osquery in OSX"
    _PKG="$(echo $_OSQUERY_PKG | cut -d"/" -f5)"
    sudo curl -# "$_OSQUERY_PKG" -o "/tmp/$_PKG"
    sudo installer -pkg "/tmp/$_PKG" -target /
  fi
  if [ "$OS" = "freebsd" ]; then
    log "Installing osquery in FreeBSD"
    sudo ASSUME_ALWAYS_YES=YES pkg install osquery
  fi
}

verifyOsquery() {
  osqueryi=$(which osqueryi)
  if [ "$?" = "1" ]; then
    #read -p "[+] $_PROJECT needs osquery. Do you want to install it? [y/n]" yn
    #case $yn in
    #  [Yy]* ) installOsquery;;
    #  [Nn]* ) exit 1;;
    #  * ) exit 1;;
    #esac
    log "[+] $_PROJECT needs osquery"
    installOsquery
  else
    osqueryi -version
  fi
}

whatOS() {
  OS=$(echo $(uname)|tr '[:upper:]' '[:lower:]')
  log "OS=$OS"
  if [ "$OS" = "linux" ]; then
    _SECRET_FILE="$_SECRET_LINUX"
    _FLAGS="$_FLAGS_LINUX"
    _CERT="$_CERT_LINUX"
    _SERVICE="$_OSQUERY_SERVICE_LINUX"
  fi
  if [ "$OS" = "darwin" ]; then
    _SECRET_FILE="$_SECRET_OSX"
    _FLAGS="$_FLAGS_OSX"
    _CERT="$_CERT_OSX"
    _SERVICE="$_OSQUERY_SERVICE_OSX"
  fi
  if [ "$OS" = "freebsd" ]; then
    _SECRET_FILE="$_SECRET_FREEBSD"
    _FLAGS="$_FLAGS_FREEBSD"
    _CERT="$_CERT_FREEBSD"
    _SERVICE="$_OSQUERY_SERVICE_FREEBSD"
  fi
  log "_SECRET_FILE=$_SECRET_FILE"
  log "_FLAGS=$_FLAGS"
  log "_CERT=$_CERT"
  log "IMPORTANT! If osquery is not installed, it will be installed."
}

stopOsquery() {
  if [ "$OS" = "linux" ]; then
    log "Stopping $_OSQUERY_SERVICE_LINUX"
    if which systemctl >/dev/null; then
      sudo systemctl stop "$_OSQUERY_SERVICE_LINUX"
    elif which service >/dev/null; then
      sudo service "$_OSQUERY_SERVICE_LINUX" stop
    else
      sudo /etc/init.d/"$_OSQUERY_SERVICE_LINUX" stop
    fi
  fi
  if [ "$OS" = "darwin" ]; then
    log "Stopping $_OSQUERY_SERVICE_OSX"
    if launchctl list | grep -qcm1 "$_OSQUERY_SERVICE_OSX"; then
      sudo launchctl unload "$_PLIST_OSX"
    fi
  fi
  if [ "$OS" = "freebsd" ]; then
    log "Stopping $_OSQUERY_SERVICE_FREEBSD"
    if [ "$(service osqueryd onestatus)" = "osqueryd is running." ]; then
      sudo service "$_OSQUERY_SERVICE_FREEBSD" onestop
    fi
  fi
}

prepareSecret() {
  log "Preparing osquery secret"
  echo "$_SECRET" | sudo tee "$_SECRET_FILE"
  sudo chmod 700 "$_SECRET_FILE"
}

prepareFlags() {
  log "Preparing osquery flags"
  sudo sh -c "cat <<EOF | sed -e 's@__SECRET_FILE__@$_SECRET_FILE@g' | sed 's@__CERT_FILE__@$_CERT@g' > $_FLAGS
{{ .Environment.Flags }}
EOF"
}

prepareCert() {
  log "Preparing osquery certificate"
  sudo mkdir -p $(dirname "$_CERT")
  sudo sh -c "cat <<EOF > $_CERT
{{ .Environment.Certificate }}
EOF"
}

startOsquery() {
  if [ "$OS" = "linux" ]; then
    log "Starting $_OSQUERY_SERVICE_LINUX"
    if which systemctl >/dev/null; then
      sudo systemctl start "$_OSQUERY_SERVICE_LINUX"
      sudo systemctl enable "$_OSQUERY_SERVICE_LINUX"
    else
      sudo /etc/init.d/"$_OSQUERY_SERVICE_LINUX" start
      sudo update-rc.d "$_OSQUERY_SERVICE_LINUX" defaults
    fi
  fi
  if [ "$OS" = "darwin" ]; then
    log "Starting $_OSQUERY_SERVICE_OSX"
    sudo cp "$_OSQUERY_PLIST" "$_PLIST_OSX"
    sudo launchctl load "$_PLIST_OSX"
  fi
  if [ "$OS" = "freebsd" ]; then
    log "Starting $_OSQUERY_SERVICE_FREEBSD"
    echo 'osqueryd_enable="YES"' | sudo tee -a /etc/rc.conf
    sudo service "$_OSQUERY_SERVICE_FREEBSD" start
  fi
}

bye() {
  result=$?
  if [ "$result" != "0" ]; then
    echo "[!] Fail to enroll $_PROJECT node"
  fi
  exit $result
}

trap "bye" EXIT
whatOS
verifyOsquery
set -e
stopOsquery
prepareSecret
prepareFlags
prepareCert
startOsquery

log "Congratulations! The node has been enrolled in $_PROJECT"
log "REMINDER! $_SERVICE has been started and enabled."

# EOF
`

// QuickAddScriptPowershell to keep the raw template for the quick add powershell script
const QuickAddScriptPowershell = `
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
$osqueryMSI = "https://osquery-packages.s3.amazonaws.com/windows/osquery-5.2.2.msi"
$osqueryTempMSI = "C:\Windows\Temp\osquery-5.2.2.msi"
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
`

// QuickRemoveScriptShell to keep the raw template for the quick remove shell script
const QuickRemoveScriptShell = `
#!/bin/sh
#
# {{ .Project }} - Tool to quick-remove OSX/Linux nodes
#
# IMPORTANT! osquery will not be removed.

_PROJECT="{{ .Project }}"
_SECRET_LINUX=/etc/osquery/${_PROJECT}.secret
_FLAGS_LINUX=/etc/osquery/osquery.flags
_CERT_LINUX=/etc/osquery/certs/${_PROJECT}.crt

_SECRET_OSX=/private/var/osquery/${_PROJECT}.secret
_FLAGS_OSX=/private/var/osquery/osquery.flags
_CERT_OSX=/private/var/osquery/certs/${_PROJECT}.crt
_PLIST_OSX=/Library/LaunchDaemons/io.osquery.agent.plist

_SECRET_FREEBSD=
_FLAGS_FREEBSD=
_CERT_FREEBSD=

_OSQUERY_SERVICE_LINUX="osqueryd"
_OSQUERY_SERVICE_OSX="io.osquery.agent"
_OSQUERY_SERVICE_FREEBSD="osqueryd"

_SECRET_FILE=""
_FLAGS=""
_CERT=""
_SERVICE=""

fail() {
  echo "[!] $1"
  exit 1
}

log() {
  echo "[+] $1"
}

whatOS() {
	OS=$(echo $(uname)|tr '[:upper:]' '[:lower:]')
  log "OS=$OS"
  if [ "$OS" = "linux" ]; then
    _SECRET_FILE="$_SECRET_LINUX"
    _FLAGS="$_FLAGS_LINUX"
    _CERT="$_CERT_LINUX"
    _SERVICE="$_OSQUERY_SERVICE_LINUX"
  fi
  if [ "$OS" = "darwin" ]; then
    _SECRET_FILE="$_SECRET_OSX"
    _FLAGS="$_FLAGS_OSX"
    _CERT="$_CERT_OSX"
    _SERVICE="$_OSQUERY_SERVICE_OSX"
  fi
  log "_SECRET_FILE=$_SECRET_FILE"
  log "_FLAGS=$_FLAGS"
  log "_CERT=$_CERT"
  log "_SERVICE=$_SERVICE"
  log "IMPORTANT! osquery will not be removed."
}

stopOsquery() {
  if [ "$OS" = "linux" ]; then
    log "Stopping $_OSQUERY_SERVICE_LINUX"
    if which systemctl >/dev/null; then
      sudo systemctl stop "$_OSQUERY_SERVICE_LINUX"
      sudo systemctl disable "$_OSQUERY_SERVICE_LINUX"
    elif which service >/dev/null; then
      sudo service "$_OSQUERY_SERVICE_LINUX" stop
      echo manual | sudo tee "/etc/init/$_OSQUERY_SERVICE_LINUX.override"
    else
      sudo /etc/init.d/"$_OSQUERY_SERVICE_LINUX" stop
      sudo update-rc.d -f "$_OSQUERY_SERVICE_LINUX" remove
    fi
  fi
  if [ "$OS" = "darwin" ]; then
    log "Stopping $_OSQUERY_SERVICE_OSX"
    if launchctl list | grep -qcm1 "$_OSQUERY_SERVICE_OSX"; then
      sudo launchctl unload "$_PLIST_OSX"
      sudo rm -f "$_PLIST_OSX"
    fi
  fi
  if [ "$OS" = "freebsd" ]; then
    log "Stopping $_OSQUERY_SERVICE_FREEBSD"
    if [ "$(service osqueryd onestatus)" = "osqueryd is running." ]; then
      sudo service "$_OSQUERY_SERVICE_FREEBSD" onestop
    fi
    cat /etc/rc.conf | grep "osqueryd_enable" | sed 's/YES/NO/g' | sudo tee /etc/rc.conf
  fi
}

removeSecret() {
  log "Removing osquery secret: $_SECRET_FILE"
  sudo rm -f "$_SECRET_FILE"
}

removeFlags() {
  log "Removing osquery flags: $_FLAGS"
  sudo rm -f "$_FLAGS"
}

removeCert() {
  log "Removing osquery certificate"
  sudo rm -f "$_CERT"
}

bye() {
  result=$?
  if [ "$result" != "0" ]; then
    echo "[!] Fail to remove $_PROJECT node"
  fi
  exit $result
}

trap "bye" EXIT
whatOS
set -e
stopOsquery
removeSecret
removeFlags
removeCert

log "Congratulations! The node has been removed from $_PROJECT"
log "WARNING! $_SERVICE has been stopped and disabled."

# EOF
`

// QuickRemoveScriptPowershell to keep the raw template for the quick remove powershell script
const QuickRemoveScriptPowershell = `
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
`
