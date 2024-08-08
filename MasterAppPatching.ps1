<#
    .SYNOPSIS
    Master application patching script for vulnerability management

    .DESCRIPTION
    Checks to see if there is an active Zoom or Teams call, if not, proceeds with application update logic. Script will prompt for user approval to restart applications if a user is logged on, otherwise, script will update
    required applications and auto close the apps if needed.

    Target applications include:
    - Microsoft Teams
    - Zoom Client
    - Google Chrome
    - Microsoft Edge
    - Firefox
    - Microsoft 365 Apps for Business
    - Windows 11 Feature Updates: Feature Update is retrieving end users approval only. This generates RMM alerts and tasks within RMM system to start the Feature Update silently in the background.

    Dependencies Include Syncro RMM module for application updates that need to be kicked off as admin. If an app update or install is required rather than an app restart, the system will generate the appropriate Broadcast Message
    RMM alerts on the device, and log the activity in Syncro, which will trigger automation rules in Syncro to kick off the corresponding scripts.

    .PARAMETER AppName
    Specifies the app ID to be updated. This processes the correct logic for the specific application

    .PARAMETER Override
    Specifies whether to override the pending update check. Default is $false.

    .INPUTS
    -appName. Supply the Application Name
    -Override. Supply the Override option

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
    [string]$AppName,
    [switch]$Override
)

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

Function Get-Config {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigFilePath
    )

    return Get-Content -Path $ConfigFilePath | ConvertFrom-Json
}

function PendingUpdateCheck {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppName
    )

    $updatePending = "no"

    if ($AppName -eq "Win11FeatureUpdate") {
        # Check Windows version against target version in the configuration
        $targetVersion = [version]$config.Applications[$AppName].TargetVersion
        $currentVersion = [version]([System.Environment]::OSVersion.Version)
        
        if ($currentVersion -lt $targetVersion) {
            $updatePending = "yes"
        } else {
            Write-Output "Current Windows version $currentVersion is already at or above the target version $targetVersion."
        }
    } else {
        # Check if the application has a pending update
        if ($config.Applications.PSObject.Properties.Name -contains $AppName) {
            $appConfig = $config.Applications[$AppName]
            if ($appConfig.CheckPath -and (Test-Path $appConfig.CheckPath)) {
                $updatePending = "yes"
            }
        }
    }

    return $updatePending
}


function Test-UserLoggedIn {
    $users = quser 2>&1
    if ($users -like "*No user exists*") {
        return $false
    } else {
        return $true
    }
}

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

function Stop-Processes {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ProcessNames
    )

    $detail = @()
    $errorCode = 0
    $stoppedProcesses = @()

    foreach ($processName in $ProcessNames) {
        $detail += "Checking for process: $processName"
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($processes) {
            foreach ($process in $processes) {
                try {
                    if ($process.MainWindowHandle -ne 0) {
                        $process.CloseMainWindow() | Out-Null
                        $timeout = 0
                        while (!$process.HasExited -and $timeout -lt 5) {
                            Start-Sleep -Seconds 1
                            $timeout++
                        }
                    }

                    if (!$process.HasExited) {
                        $process | Stop-Process -Force
                        $detail += "Process $processName forcefully stopped."
                    } else {
                        $detail += "Process $processName successfully stopped."
                    }

                    $stoppedProcesses += $processName
                } catch {
                    $detail += "An error occurred while stopping $processName $_"
                    $errorCode = 1
                }
            }
        } else {
            $detail += "Process $processName not running or not found."
        }
    }

    return [PSCustomObject]@{
        ErrorCode = $errorCode
        Detail = $detail -join "`n"
        StoppedProcesses = $stoppedProcesses
    }
}

function Restart-Processes {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ProcessNames,
        [string]$Arguments = ""
    )

    $detail = @()
    $errorCode = 0

    $processNamesToRestart = $ProcessNames | Select-Object -Unique

    foreach ($processName in $processNamesToRestart) {
        $detail += "Restarting process: $processName"
        try {
            if ($Arguments) {
                Start-Process -FilePath $processName -ArgumentList $Arguments
            } else {
                Start-Process -FilePath $processName
            }
            $detail += "Process $processName successfully restarted."
        } catch {
            $detail += "Failed to restart process $processName."
            $errorCode = 88
        }
    }

    return [PSCustomObject]@{
        ErrorCode = $errorCode
        Detail = $detail -join "`n"
    }
}

function Update-Application {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppName,
        [string[]]$ProcessNames,
        [string]$RestartArguments = ""
    )

    $detail = @()
    $errorCode = 0

    $detail += "Updating $AppName..."

    # Stop processes
    $stopResult = Stop-Processes -ProcessNames $ProcessNames
    $detail += $stopResult.Detail
    if ($stopResult.ErrorCode -ne 0) {
        return [PSCustomObject]@{
            ResultCode = $stopResult.ErrorCode
            Detail = $detail -join "`n"
        }
    }

    Start-Sleep -Seconds 3

    # Restart processes
    $restartResult = Restart-Processes -ProcessNames $stopResult.StoppedProcesses -Arguments $RestartArguments
    $detail += $restartResult.Detail
    if ($restartResult.ErrorCode -ne 0) {
        return [PSCustomObject]@{
            ResultCode = $restartResult.ErrorCode
            Detail = $detail -join "`n"
        }
    }

    return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n"
    }
}

function Create-ScheduledTask {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppName,
        [datetime]$ScheduleTime
    )

    $detail = @()
    $errorCode = 0

    $scriptDirectory = $config.ScriptDirectory
    $scriptPath = "$scriptDirectory\\Update-$AppName.ps1"
    $processNames = $config.Applications[$AppName].ProcessNames -join "', '"

    $scriptContent = @"
# Auto-generated script to update $AppName
param(
    [Parameter(Mandatory=\$true)]
    [string]`$AppName
)

# Define a function to restart the application
function Restart-Processes {
    param(
        [Parameter(Mandatory=\$true)]
        [string[]]`$ProcessNames,
        [string]`$Arguments = ""
    )

    `$detail = @()
    `$errorCode = 0

    `$processNamesToRestart = `$ProcessNames | Select-Object -Unique

    foreach (`$processName in `$processNamesToRestart) {
        `$detail += "Restarting process: `$processName"
        try {
            if (`$Arguments) {
                Start-Process -FilePath `$processName -ArgumentList `$Arguments
            } else {
                Start-Process -FilePath `$processName
            }
            `$detail += "Process `$processName successfully restarted."
        } catch {
            `$detail += "Failed to restart process `$processName."
            `$errorCode = 88
        }
    }

    return [PSCustomObject]@{
        ErrorCode = `$errorCode
        Detail = `$detail -join "`n"
    }
}

# Stop and restart the processes for the application
Update-Application -AppName `$AppName -ProcessNames '$processNames'
"@

    try {
        # Write the script content to a file
        Set-Content -Path $scriptPath -Value $scriptContent -Force
        $detail += "Script file for $AppName created successfully at $scriptPath."

        $scriptArguments = "-AppName '$AppName'"
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -File `"$scriptPath`" $scriptArguments"
        $trigger = New-ScheduledTaskTrigger -At $ScheduleTime -Once

        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Update$AppName" -Force
        $detail += "Scheduled task for $AppName created successfully."
    } catch {
        $detail += "Failed to create script file or scheduled task for $AppName."
        $errorCode = 1
    }

    return [PSCustomObject]@{
        ResultCode = $errorCode
        Detail = $detail -join "`n"
    }
}


#ScriptBlock for Teams update
$TeamsUpdate = {
    Update-Application -AppName "Teams" -ProcessNames @('Teams', 'ms-teams')
}

$ChromeUpdate = {
    Update-Application -AppName "Chrome" -ProcessNames @('chrome') -RestartArguments "--restore-last-session"
}

$EdgeUpdate = {
    Update-Application -AppName "Edge" -ProcessNames @('edge', 'ms-edge') -RestartArguments "--restore-last-session"
}

$FirefoxUpdate = {
    Update-Application -AppName "Firefox" -ProcessNames @('Firefox')
}

$M365AppsUpdate = {
    Update-Application -AppName "M365Apps" -ProcessNames @('excel', 'powerpnt', 'winword', 'outlook', 'onenote', 'visio')
}

$Win11FeatureUpdate = {
    $detail = @() # Array to capture detail messages
    $errorCode = 0 # Set the default errorcode to 0, other scriptblocks may adjust the errorcode
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
    if (Test-Path $config.LogoFilePath) {
        $pictureBox.Image = [System.Drawing.Image]::FromFile($config.LogoFilePath)
        $pictureBox.Size = New-Object System.Drawing.Size(176, 73) # Adjust size as needed
        $pictureBox.Location = New-Object System.Drawing.Point(120, 10) # Adjust location as needed
    }

    # Label to State The Application Needs to be Restarted
    $labelRestartRequired = New-Object System.Windows.Forms.Label
    switch ($AppName) {
        "Edge" {
            $labelRestartRequired.Text = "Microsoft Edge Restart Required"
        }
        "Chrome" {
            $labelRestartRequired.Text = "Google Chrome Restart Required"
        }
        "Firefox" {
            $labelRestartRequired.Text = "Mozilla Firefox Restart Required"
        }
        "Teams" {
            $labelRestartRequired.Text = "Microsoft Teams Restart Required"
        }
        "M365Apps" {
            $labelRestartRequired.Text = "Microsoft 365/Office Apps Restart Required"
        }
        "Win11FeatureUpdate" {
            $labelRestartRequired.Text = "Windows 11 Feature Update Required. Please Approve or Schedule."
        }
    }

    $labelRestartRequired.AutoSize = $true
    $labelRestartRequired.Location = New-Object System.Drawing.Point(25, 110)
    $labelRestartFont = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
    $labelRestartRequired.Font = $labelRestartFont

    # Label for additional info
    $labelAdditionalInfo = New-Object System.Windows.Forms.Label
    switch ($AppName) {
        "Edge" {
            $labelAdditionalInfo.Text = "Microsoft Edge needs to be restarted to apply important security updates. Pressing Restart $AppName Now will immediately close the Microsoft Edge browser and reopen it. If you have open tabs, you will need to click the Restore Tabs button to reload those tabs. Save open items in $appname before proceeding. Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
        }
        "Chrome" {
            $labelAdditionalInfo.Text = "Pressing Restart $AppName Now will immediately close the Google Chrome browser and reopen it. If you have open tabs, you will need to click the Restore Tabs button to reload those tabs. Save open items in $appname before proceeding. Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
        }
        "Firefox" {
            $labelAdditionalInfo.Text = "Pressing Restart $AppName Now will immediately close the application and restart it. Save open items in $appname before proceeding. Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
        }
        "Teams" {
            $labelAdditionalInfo.Text = "Pressing Restart $AppName Now will immediately close the Microsoft Teams application and reopen it. Save open items in $appname before proceeding. Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
        }
        "M365Apps" {
            $labelAdditionalInfo.Text = "Pressing Restart $AppName Now will immediately close any open Office applications (Word, Excel, PowerPoint, Outlook, Visio, OneNote). Please save all work before proceeding. Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
        }
        "Win11FeatureUpdate" {
            $labelAdditionalInfo.Text = "Pressing the Start Feature Update Now button will start an automated installation process in the background. THIS WILL AUTOMATICALLY RESTART YOUR COMPUTER WITHOUT NOTICE. Please save all work before proceeding. Click Schedule for 7PM to schedule this task to occur at 7PM tonight."
        }
    }

    $labelAdditionalInfo.Size = New-Object System.Drawing.Size(380, 130)
    $labelAdditionalInfo.Location = New-Object System.Drawing.Point(10, 200)
    $labelFont = New-Object System.Drawing.Font("Arial", 10)
    $labelAdditionalInfo.Font = $labelFont

    # Timer label
    $labelTimer = New-Object System.Windows.Forms.Label
    $labelTimer.Text = 'Seconds left to restart:'
    $labelTimer.Location = New-Object System.Drawing.Point(140, 160)

    # Dynamic timer label
    $labelTime = New-Object System.Windows.Forms.Label
    $labelTime.Text = '300'
    $labelTime.Location = New-Object System.Drawing.Point(240, 170)

    # Restart Now button
    $ButtonRestartNow = New-Object System.Windows.Forms.Button
    switch ($AppName) {
        "Win11FeatureUpdate" {
            $ButtonRestartNow.Text = "Start Feature Update Now"
        }
        default {
            $ButtonRestartNow.Text = "Restart $AppName Now"
        }
    }

    $ButtonRestartNow.Location = New-Object System.Drawing.Point(10, 340)
    $ButtonRestartNow.Size = New-Object System.Drawing.Size(100, 40)
    $ButtonRestartNow.Add_Click({
        # Call the appropriate script block based on the app name
        switch ($appName) {
            "Win11FeatureUpdate" {
                $output = & $Win11FeatureUpdate
            }
            "Teams" {
                $output = & $TeamsUpdate
            }
            "Edge" {
                $output = & $EdgeUpdate
            }
            "Chrome" {
                $output = & $ChromeUpdate
            }
            "Firefox" {
                $output = & $FirefoxUpdate
            }
            "M365Apps" {
                $output = & $M365AppsUpdate
            }
            default {
                $output = Update-Application -AppName $appname -ProcessNames $config.Applications[$appname].ProcessNames
            }
        }
        
        # Store the output in the script-scoped variable
        $script:formOutput = $output
        # Close the form
        $MainForm.Close()
    })

    # Schedule button
    $ButtonSchedule = New-Object System.Windows.Forms.Button
    $ButtonSchedule.Text = 'Schedule - 7pm'
    $ButtonSchedule.Location = New-Object System.Drawing.Point(140, 340)
    $ButtonSchedule.Size = New-Object System.Drawing.Size(100, 40)
    $ButtonSchedule.Add_Click({
        # Call the appropriate scheduled task creation based on the app name
        $scheduleTime = (Get-Date).Date.AddHours(19)
        $output = Create-ScheduledTask -AppName $appName -ScheduleTime $scheduleTime

        # Store the output in the script-scoped variable
        $script:formOutput = $output
        # Close the form
        $MainForm.Close()
    })

    # Cancel button
    $ButtonCancel = New-Object System.Windows.Forms.Button
    $ButtonCancel.Text = 'Cancel'
    $ButtonCancel.Location = New-Object System.Drawing.Point(270, 340)
    $ButtonCancel.Size = New-Object System.Drawing.Size(100, 40)
    $ButtonCancel.Add_Click({
        # Call the CancelButtonTasks script block
        $output = & $CancelButtonTasks
        # Store the output in the script-scoped variable
        $script:formOutput = $output
        # Close the form
        $MainForm.Close()
    })

    # Timer for countdown
    $timerUpdate = New-Object System.Windows.Forms.Timer
    $timerUpdate.Interval = 1000 # Update every second
    $timerUpdate.Add_Tick({
        $labelTime.Text = [int]$labelTime.Text - 1
        if ($labelTime.Text -eq '0') {
            $timerUpdate.Stop()
            switch ($appName) {
                "Win11FeatureUpdate" {
                    $script:formOutput = & $Win11FeatureUpdate
                }
                default {
                    $script:formOutput = Update-Application -AppName $appname -ProcessNames $config.Applications[$appname].ProcessNames
                }
            }
            $MainForm.Close()
        }
    })

    # Add controls to the form
    $MainForm.Controls.Add($pictureBox)
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

# Load the configuration file
$config = Get-Config -ConfigFilePath "C:\\GitHub\\MasterAppPatching\\config.json"

# Main script execution starts here
Write-Output "1. This is the beginning of the script, appName is $appName"

# Check if appName has pending update, if not, exit script
if (-not $Override) {
    Write-Output "2. Checking for pending update of $appName"
    $isUpdatePending = PendingUpdateCheck -AppName $appname

    if ($isUpdatePending -eq "No") {
        Write-Output "2. $appName is not pending an update, nothing to do, exiting script"
        Return 100
    } else {
        Write-Output "2. $appName has a pending update, continuing with script"
    }
} else {
    Write-Output "2. Override is enabled, skipping pending update check"
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