# AD & File Share Test Environment Generator

## tldr;
This PowerShell script (`User-Group-File-Generator.ps1`) automates the creation and destruction of a complete Active Directory and file share testing environment. Use it to quickly spin up users, groups, folders, and large test files with specific permissions, and then tear it all down with a single command when you're done.

---

### Basic Operations

The script is controlled by parameters passed to it on the command line.

#### Key Parameters

*   `-ProjectPrefix "name"`: The unique name for your test environment (e.g., "WebAppTest"). Defaults to `"sssd_demo"`.
*   `-RootPath "C:\Path"`: The parent folder where the test directory structure will be created. Defaults to `"C:\Temp"`.
*   `-UserCount <number>`: How many users to create for *each* specific role group (e.g., Sales Read-Only, Engineering Read-Write, etc.). Defaults to `1`.
*   `-FileCount <number>`: How many large, unique data files to create in each test folder. Defaults to `25`.
*   `-UserPassword "password"`: Sets the password for all created users. Defaults to `"Password123!"`.
*   `-Cleanup`: A switch that tells the script to delete all AD objects and folders associated with the `-ProjectPrefix`.

---

### Usage Examples

#### 1. Create a Default Environment
This command creates an environment named `sssd_demo` with 1 user per role group and 25 files per folder.

```powershell
.\User-Group-File-Generator.ps1
```

#### 2. Create a Custom Environment

This command creates a more complex environment named projectx with 4 users per role group (for a total of 36 users), 10 files per folder, and a custom password.
powershell

```powershell
.\User-Group-File-Generator.ps1 -ProjectPrefix "ProjectX" -UserCount 4 -FileCount 10 -UserPassword "MyP@ssw0rd!"
```

#### 3. Clean Up an Environment

This command will find and delete the OU, users, groups, SMB share, and all folders/files associated with the projectx environment. This is destructive and will ask for confirmation.
powershell

```powershell
.\User-Group-File-Generator.ps1 -ProjectPrefix "ProjectX" -Cleanup
```

