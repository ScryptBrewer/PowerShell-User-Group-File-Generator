<#
.SYNOPSIS
    Creates or cleans up a complete Active Directory and File System environment for testing permissions.

.DESCRIPTION
    This script can be run in two modes:
    1. Creation Mode (Default): Creates a new OU, security groups (with role groups nested into a main group), dedicated users for each role, 
       a folder structure with large unique files, NTFS permissions, and an SMB share. All names are based on the ProjectPrefix.
    2. Cleanup Mode (-Cleanup): Removes the OU, the SMB share, and the entire folder structure created by this script.

.PARAMETER ProjectPrefix
    The unique name for the project. All generated names will be based on this and converted to lowercase.

.PARAMETER RootPath
    The parent directory where the project folder structure will be created (e.g., "C:\Temp").
    
.PARAMETER UserPassword
    The password to set for all created test users.

.PARAMETER UserCount
    The number of test users to create *per specific role group*. For example, a value of 2 will create two users for Sales_RW, 
    two for Sales_RO, etc.

.PARAMETER FileCount
    The number of test files to create in each departmental and public folder.

.PARAMETER MinFileSizeMB
    The minimum size in Megabytes for the generated test files.

.PARAMETER MaxFileSizeMB
    The maximum size in Megabytes for the generated test files.
    
.PARAMETER Cleanup
    A switch parameter that, when present, will delete all AD and file system objects associated with the ProjectPrefix.

.EXAMPLE
    .\Create-TestEnvironment.ps1 -ProjectPrefix "WebAppTest" -UserCount 2
    Creates a new environment named 'webapptest' with correctly named users and short logon names (e.g., web-sal-rw-01).

.EXAMPLE
    .\Create-TestEnvironment.ps1 -ProjectPrefix "WebAppTest" -Cleanup
    Removes the 'webapptest' OU, SMB share, and all associated folders and files.
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$ProjectPrefix = "SSSD_Demo",

    [Parameter(Mandatory = $false)]
    [string]$RootPath = "C:\Temp",

    [Parameter(Mandatory = $false)]
    [string]$UserPassword = "Password123!",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$UserCount = 4,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 100)]
    [int]$FileCount = 25,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1024)]
    [int]$MinFileSizeMB = 1,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 2048)]
    [int]$MaxFileSizeMB = 500,

    [Parameter(Mandatory = $false)]
    [switch]$Cleanup
)

# --- SCRIPT START ---

# Verify prerequisites
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "FATAL: The Active Directory PowerShell module is not available. Please run this script on a Domain Controller or a machine with RSAT for AD DS installed." -ForegroundColor Red
    return
}

if ($MinFileSizeMB -gt $MaxFileSizeMB) {
    Write-Host "FATAL: MinFileSizeMB cannot be greater than MaxFileSizeMB." -ForegroundColor Red
    return
}

# --- DEFINE DYNAMIC NAMES (ALL LOWERCASE) ---
$ProjectPrefix = $ProjectPrefix.ToLower()
$OUName = $ProjectPrefix
$DemoRootPath = Join-Path $RootPath $ProjectPrefix
$ShareName = "${ProjectPrefix}_publicshare"
$DomainDN = (Get-ADDomain).DistinguishedName
$OUDN = "OU=$OUName,$DomainDN"
$AllUsersGroupName = "${ProjectPrefix}_users"

# --- CLEANUP MODE ---
if ($Cleanup) {
    Write-Host "--- CLEANUP MODE INITIATED for project '$ProjectPrefix' ---" -ForegroundColor Yellow
    $Confirmation = Read-Host "ARE YOU SURE you want to permanently delete the AD OU, SMB Share, and all folders/files? (y/n)"
    if ($Confirmation -ne 'y') { Write-Host "Cleanup aborted by user."; return }

    if (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue) { try { Remove-SmbShare -Name $ShareName -Force; Write-Host "[SUCCESS] Removed SMB Share: $ShareName" -ForegroundColor Green } catch { Write-Host "[FAIL] Could not remove SMB Share. Error: $_" -ForegroundColor Red } } else { Write-Host "[INFO] SMB Share not found." -ForegroundColor Yellow }
    if (Test-Path $DemoRootPath) { try { Remove-Item -Path $DemoRootPath -Recurse -Force; Write-Host "[SUCCESS] Removed folder structure: $DemoRootPath" -ForegroundColor Green } catch { Write-Host "[FAIL] Could not remove folder structure. Error: $_" -ForegroundColor Red } } else { Write-Host "[INFO] Root folder not found." -ForegroundColor Yellow }
    if (Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -ErrorAction SilentlyContinue) { try { Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" | Remove-ADOrganizationalUnit -Recursive -Confirm:$false; Write-Host "[SUCCESS] Removed OU: $OUName" -ForegroundColor Green } catch { Write-Host "[FAIL] Could not remove OU. Error: $_" -ForegroundColor Red } } else { Write-Host "[INFO] OU not found." -ForegroundColor Yellow }
    Write-Host "`n--- Cleanup Complete ---" -ForegroundColor Green
    return
}

# --- CREATION MODE ---
Write-Host "--- CREATION MODE INITIATED for project '$ProjectPrefix' ---" -ForegroundColor Cyan
$Password = ConvertTo-SecureString $UserPassword -AsPlainText -Force
$Departments = @{ "Sales" = "sal"; "Engineering" = "eng"; "HR" = "hr" }
$PermissionLevels = @{ "RO" = "ReadAndExecute, Synchronize"; "RW" = "Modify, Synchronize"; "FC" = "FullControl" }

# --- 1. Create the Organizational Unit ---
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'")) { New-ADOrganizationalUnit -Name $OUName -Path $DomainDN -ProtectedFromAccidentalDeletion $false; Write-Host "[SUCCESS] Created OU: $OUName" -ForegroundColor Green } else { Write-Host "[INFO] OU '$OUName' already exists." -ForegroundColor Yellow }

# --- 2. Create Security Groups ---
Write-Host "`nCreating Security Groups..." -ForegroundColor Cyan
if (-not (Get-ADGroup -Filter "Name -eq '$AllUsersGroupName'")) { New-ADGroup -Name $AllUsersGroupName -GroupScope Global -GroupCategory Security -Path $OUDN; Write-Host "[SUCCESS] Created Group: $AllUsersGroupName" -ForegroundColor Green } else { Write-Host "[INFO] Group '$AllUsersGroupName' already exists." -ForegroundColor Yellow }
foreach ($dept in $Departments.Keys) {
    foreach ($level in $PermissionLevels.Keys) {
        $GroupName = "${ProjectPrefix}_${dept}_${level}".ToLower()
        if (-not (Get-ADGroup -Filter "Name -eq '$GroupName'")) { New-ADGroup -Name $GroupName -GroupScope Global -GroupCategory Security -Path $OUDN; Write-Host "[SUCCESS] Created Group: $GroupName" -ForegroundColor Green } else { Write-Host "[INFO] Group '$GroupName' already exists." -ForegroundColor Yellow }
    }
}

# --- 3. Nest Role Groups into the Main User Group ---
Write-Host "`nNesting role groups into '$AllUsersGroupName'..." -ForegroundColor Cyan
$AllUsersGroup = Get-ADGroup $AllUsersGroupName
foreach ($dept in $Departments.Keys) {
    foreach ($level in $PermissionLevels.Keys) {
        $RoleGroupName = "${ProjectPrefix}_${dept}_${level}".ToLower()
        Add-ADGroupMember -Identity $AllUsersGroup -Members (Get-ADGroup $RoleGroupName)
        Write-Host "[SUCCESS] Nested '$RoleGroupName' into '$AllUsersGroupName'" -ForegroundColor Green
    }
}

# --- 4. Create Users and Assign to Groups ---
Write-Host "`nCreating Test Users for each specific group..." -ForegroundColor Cyan
$shortPrefix = ($ProjectPrefix -split '[-_]')[0] 
foreach ($dept in $Departments.Keys) {
    foreach ($level in $PermissionLevels.Keys) {
        for ($i = 1; $i -le $UserCount; $i++) {
            
            $displayName = "{0}_{1}_{2}_user{3:D2}" -f $ProjectPrefix, $dept.ToLower(), $level.ToLower(), $i
            $samAccountName = "{0}-{1}-{2}-{3:D2}" -f $shortPrefix, $Departments[$dept], $level.ToLower(), $i
            
            if ($samAccountName.Length -gt 20) {
                Write-Host "[FAIL] Generated SamAccountName '$samAccountName' is too long. Please use a shorter ProjectPrefix." -ForegroundColor Red
                continue
            }

            if (Get-ADUser -Filter "SamAccountName -eq '$samAccountName'") {
                Write-Host "[INFO] User with logon '$samAccountName' already exists." -ForegroundColor Yellow
                continue
            }
            
            # **FIXED**: Reworked parameters and error handling
            $userParams = @{
                Name                  = $samAccountName # Use the short, safe name for the CN
                SamAccountName        = $samAccountName
                DisplayName           = $displayName
                UserPrincipalName     = "$samAccountName@$($env:USERDNSDOMAIN)"
                Path                  = $OUDN
                AccountPassword       = $Password
                Enabled               = $true
                PasswordNeverExpires  = $true
                ChangePasswordAtLogon = $false
            }
            
            # **FIXED**: Robust try/catch block for user creation and group assignment
            try {
                $adUser = New-ADUser @userParams -PassThru
                Write-Host "[SUCCESS] Created User: $displayName (Logon: $samAccountName)" -ForegroundColor Green
                
                $TargetGroupName = "${ProjectPrefix}_${dept}_${level}".ToLower()
                Add-ADGroupMember -Identity $TargetGroupName -Members $adUser
                Write-Host "  -> Assigned to group '$TargetGroupName'" -ForegroundColor Gray
            }
            catch {
                Write-Host "[FAIL] Could not create or process user '$displayName'. Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# --- 5. Create Folder Structure ---
Write-Host "`nCreating Folder Structure at '$DemoRootPath'..." -ForegroundColor Cyan
if (-not (Test-Path $DemoRootPath)) { New-Item -Path $DemoRootPath -ItemType Directory | Out-Null }
$CompanyDataPath = Join-Path $DemoRootPath "CompanyData"; New-Item -Path $CompanyDataPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
$PublicSharePath = Join-Path $DemoRootPath "PublicShare"; New-Item -Path $PublicSharePath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
foreach ($dept in $Departments.Keys) { $DeptPath = Join-Path $CompanyDataPath $dept; New-Item -Path $DeptPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null; Write-Host "[SUCCESS] Created Directory: $DeptPath" -ForegroundColor Green }
Write-Host "[SUCCESS] Created Directory: $PublicSharePath" -ForegroundColor Green

# --- 6. Set NTFS Permissions ---
Write-Host "`nSetting NTFS Permissions..." -ForegroundColor Cyan
@( $CompanyDataPath, $PublicSharePath ) | ForEach-Object { $Acl = Get-Acl $_; $Acl.SetAccessRuleProtection($true, $false); Set-Acl -Path $_ -AclObject $Acl }
foreach ($dept in $Departments.Keys) {
    $DeptPath = Join-Path $CompanyDataPath $dept
    $Acl = Get-Acl -Path $DeptPath
    foreach ($level in $PermissionLevels.Keys) {
        $GroupName = "${ProjectPrefix}_${dept}_${level}".ToLower()
        $NTFSPerm = $PermissionLevels[$level]
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($GroupName, $NTFSPerm, "ContainerInherit, ObjectInherit", "None", "Allow")
        $Acl.AddAccessRule($Rule)
    }
    Set-Acl -Path $DeptPath -AclObject $Acl
    Write-Host "[SUCCESS] Set NTFS permissions for '$DeptPath'" -ForegroundColor Green
}
$Acl = Get-Acl -Path $PublicSharePath
$Rule = New-Object System.Security.AccessControl.FileSystemAccessRule($AllUsersGroupName, "Modify, Synchronize", "ContainerInherit, ObjectInherit", "None", "Allow")
$Acl.AddAccessRule($Rule)
Set-Acl -Path $PublicSharePath -AclObject $Acl
Write-Host "[SUCCESS] Set NTFS permissions for '$PublicSharePath'" -ForegroundColor Green

# --- 7. Create SMB Share ---
Write-Host "`nCreating SMB Share..." -ForegroundColor Cyan
if (-not (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue)) { New-SmbShare -Name $ShareName -Path $PublicSharePath -FullAccess 'Authenticated Users'; Write-Host "[SUCCESS] Created SMB Share '$ShareName'" -ForegroundColor Green } else { Write-Host "[INFO] SMB Share '$ShareName' already exists." -ForegroundColor Yellow }

# --- 8. Create Test Files ---
if ($FileCount -gt 0) {
    Write-Host "`nCreating $FileCount test files in each directory. This may take a while..." -ForegroundColor Cyan
    $TargetDirectories = @($PublicSharePath) + ($Departments.Keys | ForEach-Object { Join-Path $CompanyDataPath $_ })
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    foreach ($dir in $TargetDirectories) {
        $dirName = (Get-Item $dir).Name
        Write-Host "Populating directory: $dirName" -ForegroundColor Cyan
        for ($i = 1; $i -le $FileCount; $i++) {
            Write-Progress -Activity "Creating Files in '$dirName'" -Status "Processing file $i of $FileCount" -PercentComplete ($i / $FileCount * 100)
            $targetSizeMB = Get-Random -Minimum $MinFileSizeMB -Maximum ($MaxFileSizeMB + 1)
            $targetSizeBytes = $targetSizeMB * 1MB
            $fileName = "testfile_{0:D2}_({1}mb).dat" -f $i, $targetSizeMB
            $filePath = Join-Path $dir $fileName
            $fileStream = New-Object System.IO.FileStream($filePath, "Create")
            $headerText = "File: $fileName | Size: $targetSizeMB MB | GUID: $([System.Guid]::NewGuid())`r`n"
            $headerBytes = [System.Text.Encoding]::UTF8.GetBytes($headerText)
            $fileStream.Write($headerBytes, 0, $headerBytes.Length)
            $bytesWritten = $headerBytes.Length
            $buffer = New-Object byte[] 65536
            while ($bytesWritten -lt $targetSizeBytes) { $rng.GetBytes($buffer); $bytesToWrite = [System.Math]::Min($buffer.Length, $targetSizeBytes - $bytesWritten); $fileStream.Write($buffer, 0, $bytesToWrite); $bytesWritten += $bytesToWrite }
            $fileStream.Close(); $fileStream.Dispose()
        }
    }
    $rng.Dispose()
}

Write-Host "`n--- SETUP COMPLETE ---" -ForegroundColor Green
Write-Host "Project '$ProjectPrefix' has been successfully created."
Write-Host "The password for all users is '$UserPassword'."
Write-Host "To clean up, run this script again with the -Cleanup switch."