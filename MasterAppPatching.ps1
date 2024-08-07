Function MasterAppPatching {
<#
        .SYNOPSIS
        Master application patching script for vulnerability management

        .DESCRIPTION
        Checks to see if there is an active Zoom or Teams call, if not, proceeds with application update logic.  Script will prompt for user approval to restart applications if a user is logged on, otherwise, script will update
    	required applications and auto close the apps if needed.
		
		Target applications include:
		- Microsoft Teams
		- Zoom Client
		- Google Chrome
		- Microsoft Edge
		- Firefox
		- Microsoft 365 Apps for Business
		- Windows 11 Feature Updates: Feature Update is retrieving end users approval only.  This generates RMM alerts and tasks within RMM system to start the Feature Update silently in the background.
		
		Dependencies Include Syncro RMM module for application updates that need to be kicked off as admin.  If an app update or install is required rather than an app restart, the system will generate the appropriate Broadcast Message
		RMM alerts on the device, and log the activity in Syncro, which will trigger autotmation rules in Syncro to kick off the corresponding scripts.

        .PARAMETER AppName
        Specifies the app ID to be updated.  This processes the correct logic for the specific application

        .INPUTS
        -appName.  Supply the Application Name

        .OUTPUTS
        Feedback on overall progress is supplied via Write-Output
		Possible exit codes are 0(successful) 1(Failure) 2(User Pressed Cancel Button) 3(User Scheduled for later) 88(Closed application, failed to restart application) 99(User is on an active Call) 100(Selected application has no update available)

        .EXAMPLE
        PS> MasterAppPatching -AppName Teams
		PS> MasterAppPatching -AppName Firefox
		PS> MasterAppPatching -AppName Chrome
		PS> MasterAppPatching -AppName Edge
		PS> MasterAppPatching -AppName Webview2
		PS> MasterAppPatching -AppName M365Apps
		PS> MasterAppPatching -AppName Win11FeatureUpdate
		        
        .Link        		 
		Code derived from multiple sources, logic and overall script developed by Direct Business Technologies/Justin Mirsky
		# Clearing Teams Cache by Mark Vale
		# Uninstall Teams by Rudy Mens
		Details on Edge update process found at https://textslashplain.com/2023/03/25/how-microsoft-edge-updates/
		Process to close and reopen edge properly found at https://github.com/papersaltserver/PowerShell-Scripts/blob/master/Restore-EdgeTabs.ps1
		Microsoft Store app update info found at https://p0w3rsh3ll.wordpress.com/2012/11/08/search-updates-using-the-windows-store/	
    #>
#Define a Param block to use custom parameters in the project 
param(
    [Parameter(Mandatory=$true)]
    [string]$AppName
)

#To Dos:
#Configure Cancel Button and Schedule Button Exit codes
#Test Schedule Button for each app
#

#---------------------------------------------- 
#region Import Assemblies 
#---------------------------------------------- 
[void][Reflection.Assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089') 
[void][Reflection.Assembly]::Load('System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089') 
[void][Reflection.Assembly]::Load('System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a') 
#endregion Import Assemblies 
 
# Import necessary assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Define a path to the logo file
$logoFilePath = "C:\dbt-scripts\ScriptLogo.png" # Replace with your actual logo path

function PendingUpdateCheck {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppName
    )

    # Initialize the variable to "no" by default
    $updatepending = "no"

    # Perform a switch operation based on the $AppName
    switch ($AppName) {
        "Edge" {
            # Check if the Edge update file exists
            if (Test-Path "C:\Program Files (x86)\Microsoft\Edge\Application\new_msedge.exe") {
                $updatepending = "yes"
            }
        }
        "Chrome" {
            # Check if the Chrome update file exists
            ########commented out if and closing bracket to force update pending to yes
			#if (Test-Path "C:\Program Files\Google\Chrome\Application\new_chrome.exe") {
                $updatepending = "yes"
            #}
        }
        "Firefox" {
            # Check if the Firefox update directory exists and is not empty
            $firefoxUpdateDir = "C:\Program Files\Mozilla Firefox\updated"
            if (Test-Path $firefoxUpdateDir) {
                $files = Get-ChildItem -Path $firefoxUpdateDir
                if ($files.Count -gt 0) {
                    $updatepending = "yes"
                }
            }
        }
		"Teams" {
            # No Update Pending Check Available, proceed with GUI
            Write-Output "2. Teams pending update check not available, assuming update is required"
            $updatepending = "yes"
            }
		"Win11FeatureUpdate" {
			#Store OS Version Variables
			$MajorVersion = [System.Environment]::OSVersion.Version.Major
			$MinorVersion = [System.Environment]::OSVersion.Version.Minor
			$BuildVersion = [System.Environment]::OSVersion.Version.Build
			
			if ($MajorVersion -eq 10 -and $MinorVersion -eq 0 -and $BuildVersion -gt 22000) {
				Write-Output "2. Device is already on Windows 11 22H2 or higher and compliant. Nothing to do." 
			} else {
				Write-Output "2. Current Windows Version is $MajorVersion.$MinorVersion.$BuildVersion"
				Write-Output "2. Device is not compliant, Windows 11 Feature Update is required.  Setting UpdatePending to Yes"
				$updatepending = "yes"
			}
		}
			
		"M365Apps" {
           # Check if the Microsoft 365 Click2Run executable exists and if the UpdatesReadyToApply Registry Key is populated
            # Define the path to the OfficeC2RClient.exe
			$officeC2RClientPath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"

			# Define the registry path for Office updates
			$officeRegPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Updates"

			# Check if OfficeC2RClient.exe exists
			if (Test-Path -Path $officeC2RClientPath) {
				Write-Output "2. OfficeC2RClient.exe exists. Checking for updates..."

				# Check if UpdatesReadyToApply is not empty
				$updatesReady = Get-ItemProperty -Path $officeRegPath -Name "UpdatesReadyToApply" | Select-Object -ExpandProperty "UpdatesReadyToApply"

				if (![string]::IsNullOrWhiteSpace($updatesReady)) {
					Write-Host "2. M365 UpdatesReadyToApply String is populated, updates are ready to apply."
					Write-Host "2. Setting updatepending variable to Yes"
					$updatepending = "yes"
				} else {
					Write-Output "2. Microsoft 365 Apps have no updates ready to apply."
					}
			} else {
				Write-Host "2. OfficeC2RClient.exe does not exist. This might not be Microsoft 365 Apps."
				# Handle the case where OfficeC2RClient.exe is not found
			}
        }
    

        default {
            Write-Host "Unknown application name: $AppName"
        }
	}
    

    # Return the result
    return $updatepending
	
	# Example usage:
	# $isUpdatePending = PendingUpdateCheck -AppName "Edge"
	# Write-Host "Is update pending for Edge? $isUpdatePending"
}

function Test-UserLoggedIn {
    $users = quser 2>&1
    if ($users -like "*No user exists*") {
        return $false
    } else {
        return $true
    }
}

# Placeholder function for checking if a user is on an active Teams or Zoom call
function Get-CallStatus {
    # Check if Teams or Zoom processes are running
    $isTeamsOrZoomRunning = Get-Process -Name "Teams", "Zoom", "ms-teams" -ErrorAction SilentlyContinue

    # If neither Teams nor Zoom is running, return "Inactive"
    if (-not $isTeamsOrZoomRunning) {
        return "Inactive"
    }

    # Get network endpoints for the running processes
    $endpoints = Get-NetUDPEndpoint -OwningProcess $isTeamsOrZoomRunning.Id -ErrorAction SilentlyContinue
    
    # Filter out local (::) addresses
    $filteredEndpoints = $endpoints | Where-Object { $_.LocalAddress -ne "::" }

    # Check if there are any non-local endpoints
    if ($filteredEndpoints.Count -gt 0) {
        return "Active"
    } else {
        return "Inactive"
    }
}

#ScriptBlock for Teams update
$TeamsUpdate = {
	$detail = @() # Array to capture detail messages
	$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
	$detail += "5. I am in the TeamsUpdate Script Block"
	$detail += "5. Stopping Teams Process"

	# Check if Teams processes exist and stop them if they do
	$ActiveTeamsProcess = $null # Initialize as $null to store active Teams process name

	$teamsProcesses = @('Teams', 'ms-teams') # Array of possible Teams process names

	foreach ($processName in $teamsProcesses) {
		$detail += "5. Checking for process: $processName"
		$process = Get-Process -Name $processName -ErrorAction SilentlyContinue
		if ($process) {
			try {
				$process | Stop-Process -Force
				$detail += "5. Process $processName successfully stopped."
				$ActiveTeamsProcess = $processName # Store the stopped process name
				$detail += "5. Active Teams Process was $ActiveTeamsProcess"
				break # Exit the loop since we've found and stopped the process
			} catch {
				$detail += "5. An error occurred while stopping $processName"
				$detail += "5. This is where scriptblock will return status code 1"
				$errorCode = "1"
			}
		} else {
			$detail += "5. Process $processName not running or not found."
			}
	}

	# Wait for a few seconds to ensure the processes are stopped
	Start-Sleep -Seconds 3

		$detail += "5. Starting Teams Process Now"
		Start-Process $ActiveTeamsProcess #Restart Teams Client
	
		Start-Sleep -Seconds 8
	
		#Check if the Teams Process is running
		$process = Get-Process -Name $ActiveTeamsProcess -ErrorAction SilentlyContinue
		if ($process) {
			$detail += "5. $process found, Successfully restarted Teams"
			} else {
			$detail += "5. Process $processName not running or not found.  Failed to restart Teams" 
			$detail += "5. This is where scriptblock would return with status code 88"
			$errorCode = "88"
		}
		return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

$EdgeUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the EdgeUpdate Script Block"
$detail += "5. Stopping Edge Process"

# Check if Edge processes exist and stop them if they do
$ActiveEdgeProcess = $null # Initialize as $null to store active Microsoft Edge process name

$edgeProcesses = @('edge', 'ms-edge') # Array of possible Microsoft Edge process names

foreach ($processName in $edgeProcesses) {
    $detail += "5. Checking for process: $processName"
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        try {
            $process | Stop-Process -Force
            $detail += "5. Process $processName successfully stopped."
            $ActiveEdgeProcess = $processName # Store the stopped process name
            $detail += "5. Active Edge Process was $ActiveEdgeProcess"
            break # Exit the loop since we've found and stopped the process
        } catch {
            $detail += "5. An error occurred while stopping $processName"
			$detail += "5. This is where scriptblock would return with status code 1"
			$errorCode = "1"
        }
    } else {
        $detail += "5. Process $processName not running or not found."
    }
}

	# Wait for a few seconds to ensure the processes are stopped
	Start-Sleep -Seconds 3

	$detail += "5. Restarting Microsoft Edge Now"
	Start-Process $ActiveEdgeProcess -ArgumentList "--restore-last-session"  #Restart Microsoft Edge with Restore Last Session option
	
	Start-Sleep -Seconds 8
	
	#Check if the Microsoft Edge Process is running
	$process = Get-Process -Name $ActiveEdgeProcess -ErrorAction SilentlyContinue
	if ($process) {
        $detail += "5. $process found, Successfully restarted Microsoft Edge"
		} else {
        $detail += "5. Process $processName not running or not found.  Failed to restart Microsoft Edge"
		$detail += "5. This is where scriptblock would Return with status code 88"
		$errorCode = "88"
    }
	return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

$ChromeUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the ChromeUpdate Script Block"
$detail += "5. Stopping Chrome Process"

# Check if Chrome processes exist and stop them if they do
$ActiveChromeProcess = $null # Initialize as $null to store active Chrome process name

$chromeProcesses = @('chrome') # Array of possible Chrome process names

foreach ($processName in $chromeProcesses) {
    $detail += "5. Checking for process: $processName"
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        try {
            $process | Stop-Process -Force
            $detail += "5. Process $processName successfully stopped."
            $ActiveChromeProcess = $processName # Store the stopped process name
            $detail += "5. Active Chrome Process was $ActiveChromeProcess"
            break # Exit the loop since we've found and stopped the process
        } catch {
            $detail += "5. An error occurred while stopping $processName"
			$detail += "5. This is where scriptblock would return with status code 1"
			$errorCode = "1"
        }
    } else {
        $detail += "5. Process $processName not running or not found."
    }
}

	# Wait for a few seconds to ensure the processes are stopped
	Start-Sleep -Seconds 3

	$detail += "5. Restarting Google Chrome Now"
	Start-Process $ActiveChromeProcess -ArgumentList "--restore-last-session"  #Restart Google Chrome with Restore Last Session option
	
	Start-Sleep -Seconds 8
	
	#Check if the Google Chrome Process is running
	$process = Get-Process -Name $ActiveChromeProcess -ErrorAction SilentlyContinue
	if ($process) {
        $detail += "5. $process found, Successfully restarted Google Chrome"
		} else {
        $detail += "5. Process $processName not running or not found.  Failed to restart Google Chrome"
		$detail += "5. This is where script would Return with status code 88"
		$errorCode = "88"
    }
	return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

$FirefoxUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the FirefoxUpdate Script Block"
$detail += "5. Stopping Firefox Process"

# Check if Firefox processes exist and stop them if they do
$ActiveFirefoxProcess = $null # Initialize as $null to store active Firefox process name

$FirefoxProcesses = @('Firefox') # Array of possible Firefox process names

foreach ($processName in $firefoxProcesses) {
    $detail += "5. Checking for process: $processName"
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        try {
            $process | Stop-Process -Force
            $detail += "5. Process $processName successfully stopped."
            $ActiveFirefoxProcess = $processName # Store the stopped process name
            $detail += "5. Active Firefox Process was $ActiveFirefoxProcess"
            break # Exit the loop since we've found and stopped the process
        } catch {
            $detail += "5. An error occurred while stopping $processName"
			Write-Output "This is where scriptblock would return with status code 1"
			$errorCode = "1"
        }
    } else {
        $detail += "5. Process $processName not running or not found."
    }
}

	# Wait for a few seconds to ensure the processes are stopped
	Start-Sleep -Seconds 3

	$detail += "5. Restarting Mozilla Firefox Now"
	Start-Process $ActiveFirefoxProcess   #Restart Mozilla Firefox
	
	Start-Sleep -Seconds 8
	
	#Check if the Mozilla Firefox Process is running
	$process = Get-Process -Name $ActiveFirefoxProcess -ErrorAction SilentlyContinue
	if ($process) {
        $detail += "5. $process found, Successfully restarted Mozilla Firefox"
		} else {
        $detail += "5. Process $processName not running or not found.  Failed to restart Mozilla Firefox"
		$detail += "5. This is where scriptblock would return with status code 88"
		$errorCode = "88"
    }
	return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

$M365AppsUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the M365AppsUpdate Script Block"
$detail += "5. Stopping Microsoft Office Processes"

# Check if Firefox processes exist and stop them if they do
$ActiveM365AppsProcess = $null # Initialize as $null to store active Firefox process name

$M365AppProcesses = @('excel, powerpnt, winword, outlook, onenote, visio') # Array of possible Microsoft 365 Apps process names

foreach ($processName in $M365AppProcesses) {
    $detail += "5. Checking for process: $processName"
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        try {
            $process | Stop-Process -Force
            $detail += "5. Process $processName successfully stopped."
            $ActiveM365AppsProcess = $processName # Store the stopped process name
            $detail += "5. Active Microsoft 365 Apps Process was $ActiveM365AppsProcess"
            
        } catch {
            $detail += "5. An error occurred while stopping $processName"
			Write-Output "This is where scriptblock would return with status code 1"
			$errorCode = "1"
        }
    } else {
        $detail += "5. Process $processName not running or not found."
    }
}

	# Wait for a few seconds to ensure the processes are stopped
	Start-Sleep -Seconds 3

	$detail += "5. Restarting Previously Running Microsoft365 Apps Now"
	Start-Process $ActiveM365AppsProcess   #Restart Microsoft 365 Apps Firefox
	
	Start-Sleep -Seconds 15
	
	#Check if the Microsoft 365 Apps Process is running
foreach ($processName in $ActiveM365AppsProcess) {	
	$process = Get-Process -Name $processName -ErrorAction SilentlyContinue
	if ($process) {
        $detail += "5. $process found, Successfully restarted Microsoft 365 App."
		} else {
        $detail += "5. Process $processName not running or not found.  Failed to restart M365 App."
		$detail += "5. This is where scriptblock would return with status code 88"
		$errorCode = "88"
    }
}	
	return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

$Win11FeatureUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the Win11FeatureUpdate Script Block"
$detail += "5. Stopping Microsoft Office Processes"

$currentuser = [Environment]::UserName
Rmm-Alert -Category 'Win11FeatureUpdate' -Body "Windows 11 Feature Update Approved"
Broadcast-Message -Title "Feature Update Approved" -Message "$currentuser has approved the feature update for Windows 11.  This will start automatically in background.  DO NOT TURN OFF YOUR COMPUTER.  Your computer will automatically restart when the process completes."
Log-Activity -Message "Windows 11 Feature Update approved for installation by $currentuser" -EventName "Feature Update Approval"
$detail += "5. RMM Alert created to trigger the feature update script to run"
$detail += "5. Broadcast Message sent to machine to alert the user of pending upgrade"
$detail += "5. Activity has been logged against asset in Syncro feed"
	
return [PSCustomObject]@{
       ResultCode = $errorCode
       Detail = $detail -join "`n" # Join array elements into a single string
   }
}

#Scriptblock to call external Powershell script for Teams Update Scheduled Task
$TeamsScheduledUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the TeamsScheduledUpdate Script Block"
$detail += "5. Creating the Teams Update Scheduled Task Now"
    $scriptPath = "C:\dbt-scripts\TeamsScheduledUpdate.ps1"
    $scriptArguments = "-AppName 'Teams'"
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -File `"$scriptPath`" $scriptArguments"
    $trigger = New-ScheduledTaskTrigger -At 7:00PM -Once
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Update$appName" -Force
$detail += "5. Assuming scheduled task created - Need code to validate task still"
    return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

#Scriptblock to call external Powershell script for Edge Update Scheduled task
$EdgeScheduledUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the EdgeScheduledUpdate Script Block"
$detail += "5. Creating the Edge Update Scheduled Task Now"
    $scriptPath = "C:\dbt-scripts\EdgeScheduledUpdate.ps1"
    $scriptArguments = "-AppName 'Edge'"
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -File `"$scriptPath`" $scriptArguments"
    $trigger = New-ScheduledTaskTrigger -At 7:00PM -Once
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Update$appName" -Force
$detail += "5. Assuming scheduled task created - Need code to validate task still"
    return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

#Sctiptblock to call external Powershell script for Chrome Update Scheduled Task
$ChromeScheduledUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the ChromeScheduledUpdate Script Block"
$detail += "5. Creating the Chrome Update Scheduled Task Now"
    $scriptPath = "C:\dbt-scripts\ChromeScheduledUpdate.ps1"
    $scriptArguments = "-AppName 'Chrome'"
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -File `"$scriptPath`" $scriptArguments"
    $trigger = New-ScheduledTaskTrigger -At 7:00PM -Once
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Update$appName" -Force
$detail += "5. Assuming scheduled task created - Need code to validate task still"
    return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

#Sctiptblock to call external Powershell script for Firefox Update Scheduled Task
$FirefoxScheduledUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the FirefoxScheduledUpdate Script Block"
$detail += "5. Creating the Firefox Update Scheduled Task Now"
    $scriptPath = "C:\dbt-scripts\FirefoxScheduledUpdate.ps1"
    $scriptArguments = "-AppName 'Firefox'"
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -File `"$scriptPath`" $scriptArguments"
    $trigger = New-ScheduledTaskTrigger -At 7:00PM -Once
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Update$appName" -Force
$detail += "5. Assuming scheduled task created - Need code to validate task still"
    return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

#Sctiptblock to call external Powershell script for M365Apps Update Scheduled Task
$M365AppsScheduledUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the M365AppsScheduledUpdate Script Block"
$detail += "5. Creating the M365Apps Update Scheduled Task Now"
    $scriptPath = "C:\Users\User\Desktop\M365AppsScheduledUpdate.ps1"
    $scriptArguments = "-AppName 'M365Apps'"
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -File `"$scriptPath`" $scriptArguments"
    $trigger = New-ScheduledTaskTrigger -At 7:00PM -Once
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Update$appName" -Force
$detail += "5. Assuming scheduled task created - Need code to validate task still"
    return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

#Sctiptblock to call external Powershell script for Win11FeatureUpdate Update Scheduled Task
$Win11FeatureUpdateScheduledUpdate = {
$detail = @() # Array to capture detail messages
$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
$detail += "5. I am in the Win11FeatureUpdateScheduledUpdate Script Block"
$detail += "5. Creating the Win11FeatureUpdate Update Scheduled Task Now"
    $scriptPath = "C:\dbt-scripts\Win11FeatureUpdateScheduledUpdate.ps1"
    $scriptArguments = "-AppName 'Win11FeatureUpdate'"
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -File `"$scriptPath`" $scriptArguments"
    $trigger = New-ScheduledTaskTrigger -At 7:00PM -Once
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Update$appName" -Force
$detail += "5. Assuming scheduled task created - Need code to validate task still"
    return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
    }
}

#ScriptBlock to perform actions for cancel button.  Put into Script Block format to keep consistent processes throughout script.
$CancelButtonTasks = {
$detail = @() # Array to capture detail messages
$errorCode = 2 #Cancel button error code is 2
$detail += "4. I am in the Cancel Button Tasks"
$detail += "4. Cancel button was pressed, setting result code to 2"
return [PSCustomObject]@{
       ResultCode = $errorCode
       Detail = $detail -join "`n" # Join array elements into a single string
   }
}

# ScriptBlock to Update Apps (e.g., kill processes, restart apps)
$InvokeAppUpdate = {
    param($appName)
	$detail = @() # Array to capture detail messages
	$errorCode = 0 #Set the default errorcode to 0, other scriptblocks may adjust the errorcode
	
	$detail += "4. GUI Timeout Reached or User Pressed Restart App Now Button"
    $detail += "4. App to update is $appName"
    
    if ($appName -eq "Teams") {
        $detail += "4. Calling TeamsUpdate ScriptBlock Now."
		$Output = & $TeamsUpdate
		$detail += $output.detail
		$errorCode = $output.resultcode
    } elseif ($appName -eq "Edge") {
        $detail += "4. Calling EdgeUpdate ScriptBlock Now."
		$Output = & $EdgeUpdate
		$detail += $output.detail
		$errorCode = $output.resultcode
    } elseif ($appName -eq "Chrome") {
        $detail += "4. Calling ChromeUpdate ScriptBlock Now."
		$Output = & $ChromeUpdate
		$detail += $output.detail
		$errorCode = $output.resultcode
    } elseif ($appName -eq "Firefox") {
        $detail += "4. Calling M365AppsUpdate ScriptBlock Now."
		$Output = & $M365AppsUpdate
		$detail += $output.detail
		$errorCode = $output.resultcode
	} elseif ($appName -eq "Win11FeatureUpdate") {
        $detail += "4. Calling Windows11FeatureUpdate ScriptBlock Now."
		$Output = & $Win11FeatureUpdate
		$detail += $output.detail
		$errorCode = $output.resultcode
    } else {
        $detail += "4. Application is unknown, code doesn't exist for other apps yet"
		$detail += "4. This is where scriptblock would return with status code 1"
		$errorCode = "1"
    }
	# Return a custom object with both result code and detail
    return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n" # Join array elements into a single string
		}
	}

#Function to show a dialog prompt based on returned status codes
function Show-AutoClosingMessageBox {
    param(
        [string]$Message,
        [int]$TimeoutInSeconds = 10
    )

    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Message"
    $form.Size = New-Object System.Drawing.Size(300, 200)
    $form.StartPosition = "CenterScreen"
    $form.TopMost = $true

    # Create the label
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Message
    $label.Size = New-Object System.Drawing.Size(280, 140)
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $label.TextAlign = 'MiddleCenter'

    # Add label to form
    $form.Controls.Add($label)

    # Create and configure the timer
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $TimeoutInSeconds * 1000
    $timer.Add_Tick({
        # Use 'Script' scope modifier to access the form variable
        $Script:form.Close()
    })
    $timer.Start()

    # Show the form
    $form.ShowDialog() | Out-Null

    # Stop and dispose the timer after closing the form
    $timer.Stop()
    $timer.Dispose()
}

#Function to Show the Form
function Show-UpdatePromptForm {
    param($appName)

    # Create the form
    $MainForm = New-Object System.Windows.Forms.Form
    $MainForm.Text = 'Application Patching Prompt'
    $MainForm.Size = New-Object System.Drawing.Size(400, 440)
    $MainForm.StartPosition = 'CenterScreen'
	$MainForm.TopMost = $true

    # Add PictureBox for logo
    $pictureBox = New-Object System.Windows.Forms.PictureBox
    $pictureBox.SizeMode = 'StretchImage'
    if (Test-Path $logoFilePath) {
        $pictureBox.Image = [System.Drawing.Image]::FromFile($logoFilePath)
        $pictureBox.Size = New-Object System.Drawing.Size(176, 73) # Adjust size as needed
        $pictureBox.Location = New-Object System.Drawing.Point(120, 10) # Adjust location as needed
    }
	
	#Label to State The Application Needs to be Restarted
	$labelRestartRequired = New-Object System.Windows.Forms.Label
	switch ($AppName) {
		"Edge" {
            #Set the Message for Microsoft Edge
            $labelRestartRequired.Text = "Microsoft Edge Restart Required"
            }			
        "Chrome" {
            #Set the Message for Google Chrome
            $labelRestartRequired.Text = "Google Chrome Restart Required"
            }        
        "Firefox" {
            #Set the Message for Mozilla Firefox
            $labelRestartRequired.Text = "Mozilla Firefox Restart Required"
            }
		"Teams" {
            #Set the Message for Microsoft Teams
            $labelRestartRequired.Text = "Microsoft Teams Restart Required"
            }
		"M365Apps" {
			#Set the Message for Microsoft 365 Apps
            $labelRestartRequired.Text = "Microsoft 365/Office Apps Restart Required"
            }
		"Win11FeatureUpdate" {
			#Set the Message for Windows 11 Feature Update
            $labelRestartRequired.Text = "Windows 11 Feature Update Required.
			Please Approve or Schedule."
            }
	}    
	
	#$labelRestartRequired.Text = "$appName MUST be restarted to apply security updates"
    #$labelRestartRequired.Size = New-Object System.Drawing.Size(380, 130)
	$labelRestartRequired.AutoSize = $true
    $labelRestartRequired.Location = New-Object System.Drawing.Point(25, 110) #was 35, 110
	# Set font size and style
	$labelRestartFont = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold) # Arial, 14pt, Bold
	$labelRestartRequired.Font = $labelRestartFont
	
    # Label for additional info
	$labelAdditionalInfo = New-Object System.Windows.Forms.Label	
	#Set custom text in the GUI based on the application name.
	switch ($AppName) {
		"Edge" {
            #Set the Message for Microsoft Edge
            $labelAdditionalInfo.Text = "Microsoft Edge needs to be restarted to apply important security updates.  Pressing Restart $AppName Now will immediately close the Microsoft Edge browser and reopen it.  If you have open tabs, you will need to click the Restore Tabs button to reload those tabs. Save open items in $appname before proceeding. Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
            }			
        "Chrome" {
            #Set the Message for Google Chrome
            $labelAdditionalInfo.Text = "Pressing Restart $AppName Now will immediately close the Google Chrome browser and reopen it.  If you have open tabs, you will need to click the Restore Tabs button to reload those tabs. Save open items in $appname before proceeding. Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
            }        
        "Firefox" {
            #Set the Message for Mozilla Firefox
            $labelAdditionalInfo.Text = "Pressing Restart $AppName Now will immediately close the application and restart it.  Save open items in $appname before proceeding. Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
            }
		"Teams" {
            #Set the Message for Microsoft Teams
            $labelAdditionalInfo.Text = "Pressing Restart $AppName Now will immediately close the Mozilla Firefox browser and reopen it.  If you have open tabs, you will need to click the Restore Tabs button to reload those tabs. Save open items in $appname before proceeding.  Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
            }
		"M365Apps" {
			#Set the Message for Microsoft 365 Apps
            $labelAdditionalInfo.Text = "Pressing Restart $AppName Now will immediately close any open Office applications (Word, Excel, PowerPoint, Outlook, Visio, OneNote).  Please save all work before proceeding.  Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
            }
		"Win11FeatureUpdate" {
			#Set the Message for Windows 11 Feature Update
            $labelAdditionalInfo.Text = "Pressing the Start Feature Update Now button will start an automated installation process in the background.  THIS WILL AUTOMATICALLY RESTART YOUR COMPUTER WITHOUT NOTICE.  Please save all work before proceeding.  Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
            }
	}    
    #$labelAdditionalInfo.Text = "Pressing Restart $AppName Now will immediately close the application and restart it.  Save open items in $appname before proceeding."
    $labelAdditionalInfo.Size = New-Object System.Drawing.Size(380, 130)
    $labelAdditionalInfo.Location = New-Object System.Drawing.Point(10, 200) #was 150
	# Set font size and style
	$labelFont = New-Object System.Drawing.Font("Arial", 10) # Arial, 10pt
	$labelAdditionalInfo.Font = $labelFont

    # Timer label
    $labelTimer = New-Object System.Windows.Forms.Label
    $labelTimer.Text = 'Seconds left to restart:'
    $labelTimer.Location = New-Object System.Drawing.Point(140, 160) #was 140

    # Dynamic timer label
    $labelTime = New-Object System.Windows.Forms.Label
    $labelTime.Text = '300'
    $labelTime.Location = New-Object System.Drawing.Point(240, 170) #was 150

    # Restart Now button
    $ButtonRestartNow = New-Object System.Windows.Forms.Button
	switch ($AppName) {
		"Win11FeatureUpdate" {
			#Set the Button Wording for Windows 11 Feature Update
            $ButtonRestartNow.Text = "Start Feature Update Now"
            }
		default {
			#Set button text for all other applications
			$ButtonRestartNow.Text = "Restart $AppName Now"
		}
	}    
    #$ButtonRestartNow.Text = "Restart $AppName Now"
    $ButtonRestartNow.Location = New-Object System.Drawing.Point(10, 340) #was 290
    $ButtonRestartNow.Size = New-Object System.Drawing.Size(100, 40)
    $ButtonRestartNow.Add_Click({
        # Call the InvokeAppUpdate script block
        $output = & $InvokeAppUpdate $appName
        # Store the output in the script-scoped variable
        $script:formOutput = $output
        # Close the form
        $MainForm.Close()
    })
		
    # Schedule button
    $ButtonSchedule = New-Object System.Windows.Forms.Button
    $ButtonSchedule.Text = 'Schedule - 7pm'
    $ButtonSchedule.Location = New-Object System.Drawing.Point(140, 340) #was 290
    $ButtonSchedule.Size = New-Object System.Drawing.Size(100, 40)
    $ButtonSchedule.Add_Click({
	
	# Store the output in the script-scoped variable
	switch ($AppName) {
		"Edge" {
            $output = & $EdgeScheduledUpdate
            }			
        "Chrome" {
            #Set the Message for Google Chrome
            $output = & $ChromeScheduledUpdate
            }        
        "Firefox" {
            #Set the Message for Mozilla Firefox
            $output = & $FirefoxScheduledUpdate
            }
		"Teams" {
           $output = & $TeamsScheduledUpdate
            }
		"M365Apps" {
			$output = & $M365AppsScheduledUpdate
            }
		"Win11FeatureUpdate" {
			$output = & $Win11FeatureUpdateScheduledUpdate
            }
	}   
        # Store the output in the script-scoped variable
        $script:formOutput = $output

	
    $MainForm.Close()
})

    # Cancel button
    $ButtonCancel = New-Object System.Windows.Forms.Button
    $ButtonCancel.Text = 'Cancel'
    $ButtonCancel.Location = New-Object System.Drawing.Point(270, 340) #was 290
    $ButtonCancel.Size = New-Object System.Drawing.Size(100, 40)
    $ButtonCancel.Add_Click({
        #Call the CancelButton Script block
		$output = & $CancelButtonTasks
		#Store the output in the script-scoped variable
		$script:formOutput = $output
		#Close the form
		$MainForm.Close()
    })

    # Timer for countdown
    $timerUpdate = New-Object System.Windows.Forms.Timer
    $timerUpdate.Interval = 1000 # Update every second
    $timerUpdate.Add_Tick({
        $labelTime.Text = [int]$labelTime.Text - 1
        if ($labelTime.Text -eq '0') {
            $timerUpdate.Stop()
            & $InvokeAppUpdate -appName $appName
            $MainForm.Close()
        }
    })

    # Add controls to the form
    $MainForm.Controls.Add($pictureBox)
    #$MainForm.Controls.Add($labelHeader)
	$MainForm.Controls.Add($labelRestartRequired)
    $MainForm.Controls.Add($labelAdditionalInfo)
    $MainForm.Controls.Add($labelTimer)
    $MainForm.Controls.Add($labelTime)
    $MainForm.Controls.Add($ButtonRestartNow)
    $MainForm.Controls.Add($ButtonSchedule)
    $MainForm.Controls.Add($ButtonCancel)

    # Start the timer
    $timerUpdate.Start()

    # Show the form
	$MainForm.Add_Shown({
        $MainForm.Activate()
    })
    $MainForm.ShowDialog() | Out-Null
	return $script:formOutput
}

# Main script execution starts here
Write-Output "1. This is the beginning of the script, appName is $appName"

#Check if appName has pending update, if not, exit script
Write-Output "2. Checking for pending update of $appName"
$isUpdatePending = PendingUpdateCheck -AppName $appname

if ($isUpdatePending -eq "No") {
	Write-Output "2. $appName is not pending an update, nothing to do, exiting script"
	Return 100
} else {
	Write-Output "2. $appName has a pending update, continuing with script"
}
# Check call status
Write-Output "3. Checking if there is an active Teams or Zoom call"
$callStatus = Get-CallStatus
if ($callStatus -eq "Inactive") {
    Write-Output "3. There are no active Teams or Zoom calls"
	Write-Output "3. Calling GUI form to prompt end user to restart $appName"
	$output = Show-UpdatePromptForm -appName $AppName
	if ($output) {
		Write-Output $output.Detail
		Write-Output "Final Result Code from End User Prompt is $($output.ResultCode)"
	} else {
		Write-Output "No output received from the update prompt form."
	}
	Return $output.ResultCode
} else {
    Write-Output "3. The user is on an active call. Aborting the update."
	Write-Output "3. Exiting the script with status code 99"
	Return 99
	}
}
MasterAppPatching -appName $appName