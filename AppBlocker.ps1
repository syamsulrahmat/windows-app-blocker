#Requires -Version 5.1
<#
.SYNOPSIS
    AppBlocker - Block applications from accessing the internet.
.DESCRIPTION
    A simple GUI tool that creates Windows Firewall rules to block
    specific applications from making inbound/outbound connections.
    Rules are prefixed with "AppBlocker:" for easy management.
.NOTES
    Requires administrator privileges to modify firewall rules.
#>

# ── Load Assemblies ────────────────────────────────────────────────────────────
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ── Verify Administrator ──────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    [System.Windows.Forms.MessageBox]::Show(
        "AppBlocker requires administrator privileges.`nPlease run AppBlocker.bat as Administrator.",
        "Administrator Required", "OK", "Error"
    ) | Out-Null
    exit 1
}

# ── Constants ──────────────────────────────────────────────────────────────────
$RULE_PREFIX = "AppBlocker:"

# ── Helper Functions ───────────────────────────────────────────────────────────

function Get-BlockedApps {
    <# Returns a list of apps currently blocked by AppBlocker rules #>
    $rules = Get-NetFirewallRule -DisplayName "$RULE_PREFIX *" -ErrorAction SilentlyContinue |
        Where-Object { $_.Direction -eq 'Outbound' }

    $blocked = @()
    foreach ($rule in $rules) {
        $appFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        if ($appFilter -and $appFilter.Program -ne 'Any') {
            $blocked += [PSCustomObject]@{
                Name     = $rule.DisplayName -replace "^$([regex]::Escape($RULE_PREFIX))\s*", ""
                Path     = $appFilter.Program
                Enabled  = $rule.Enabled
                RuleName = $rule.DisplayName
            }
        }
    }
    return $blocked
}

function Block-Application {
    param([string]$ExePath)

    $appName = [System.IO.Path]::GetFileNameWithoutExtension($ExePath)
    $displayName = "$RULE_PREFIX $appName"

    # Check if already blocked
    $existing = Get-NetFirewallRule -DisplayName "$displayName" -ErrorAction SilentlyContinue
    if ($existing) {
        return "Already blocked: $appName"
    }

    try {
        # Block outbound (app cannot send data to internet)
        New-NetFirewallRule -DisplayName "$displayName" `
            -Direction Outbound `
            -Action Block `
            -Program $ExePath `
            -Profile Any `
            -Description "Blocked by AppBlocker on $(Get-Date -Format 'yyyy-MM-dd HH:mm')" `
            -ErrorAction Stop | Out-Null

        # Block inbound (internet cannot send data to app)
        New-NetFirewallRule -DisplayName "$displayName (Inbound)" `
            -Direction Inbound `
            -Action Block `
            -Program $ExePath `
            -Profile Any `
            -Description "Blocked by AppBlocker on $(Get-Date -Format 'yyyy-MM-dd HH:mm')" `
            -ErrorAction Stop | Out-Null

        return "Blocked: $appName"
    }
    catch {
        return "Error blocking $appName : $_"
    }
}

function Unblock-Application {
    param([string]$AppName)

    $displayName = "$RULE_PREFIX $AppName"
    try {
        Remove-NetFirewallRule -DisplayName "$displayName" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "$displayName (Inbound)" -ErrorAction SilentlyContinue
        return "Unblocked: $AppName"
    }
    catch {
        return "Error unblocking $AppName : $_"
    }
}

function Get-FirewallState {
    <# Returns firewall profiles that are currently OFF (empty array = all on) #>
    $off = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -ne $true } |
        Select-Object -ExpandProperty Name)
    return ,$off
}

function Enable-Firewall {
    try {
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop
        return $true
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Could not turn on Windows Firewall:`n$_",
            "Firewall Error", "OK", "Error"
        ) | Out-Null
        return $false
    }
}

function Stop-AppProcesses {
    <# Closes running instances of an exe so existing connections are dropped #>
    param([string]$ExePath)
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $ExePath })
    if ($procs.Count -gt 0) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    return $procs.Count
}

# ── Build GUI ──────────────────────────────────────────────────────────────────

# Main Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "AppBlocker - Internet Access Control"
$form.Size = New-Object System.Drawing.Size(620, 590)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.ForeColor = [System.Drawing.Color]::White
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)

# ── Title Label ────────────────────────────────────────────────────────────────
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "🛡  AppBlocker"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::FromArgb(100, 180, 255)
$lblTitle.Location = New-Object System.Drawing.Point(20, 12)
$lblTitle.AutoSize = $true
$form.Controls.Add($lblTitle)

$lblSubtitle = New-Object System.Windows.Forms.Label
$lblSubtitle.Text = "Block applications from accessing the internet"
$lblSubtitle.ForeColor = [System.Drawing.Color]::FromArgb(160, 160, 160)
$lblSubtitle.Location = New-Object System.Drawing.Point(22, 50)
$lblSubtitle.AutoSize = $true
$form.Controls.Add($lblSubtitle)

# ── Separator ──────────────────────────────────────────────────────────────────
$separator = New-Object System.Windows.Forms.Label
$separator.BorderStyle = "Fixed3D"
$separator.Location = New-Object System.Drawing.Point(20, 75)
$separator.Size = New-Object System.Drawing.Size(565, 2)
$form.Controls.Add($separator)

# ── Browse Section ─────────────────────────────────────────────────────────────
$lblBrowse = New-Object System.Windows.Forms.Label
$lblBrowse.Text = "Application to block:"
$lblBrowse.Location = New-Object System.Drawing.Point(20, 90)
$lblBrowse.AutoSize = $true
$form.Controls.Add($lblBrowse)

$txtPath = New-Object System.Windows.Forms.TextBox
$txtPath.Location = New-Object System.Drawing.Point(20, 112)
$txtPath.Size = New-Object System.Drawing.Size(430, 28)
$txtPath.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
$txtPath.ForeColor = [System.Drawing.Color]::White
$txtPath.BorderStyle = "FixedSingle"
$txtPath.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$txtPath.ReadOnly = $true
$form.Controls.Add($txtPath)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = "Browse..."
$btnBrowse.Location = New-Object System.Drawing.Point(458, 110)
$btnBrowse.Size = New-Object System.Drawing.Size(127, 30)
$btnBrowse.FlatStyle = "Flat"
$btnBrowse.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnBrowse.ForeColor = [System.Drawing.Color]::White
$btnBrowse.Cursor = "Hand"
$form.Controls.Add($btnBrowse)

$btnBlock = New-Object System.Windows.Forms.Button
$btnBlock.Text = "🚫  Block This App"
$btnBlock.Location = New-Object System.Drawing.Point(20, 150)
$btnBlock.Size = New-Object System.Drawing.Size(565, 36)
$btnBlock.FlatStyle = "Flat"
$btnBlock.BackColor = [System.Drawing.Color]::FromArgb(180, 50, 50)
$btnBlock.ForeColor = [System.Drawing.Color]::White
$btnBlock.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnBlock.Cursor = "Hand"
$form.Controls.Add($btnBlock)

# ── Blocked Apps List ──────────────────────────────────────────────────────────
$lblList = New-Object System.Windows.Forms.Label
$lblList.Text = "Currently Blocked Applications:"
$lblList.Location = New-Object System.Drawing.Point(20, 200)
$lblList.AutoSize = $true
$form.Controls.Add($lblList)

$listView = New-Object System.Windows.Forms.ListView
$listView.Location = New-Object System.Drawing.Point(20, 222)
$listView.Size = New-Object System.Drawing.Size(565, 190)
$listView.View = "Details"
$listView.FullRowSelect = $true
$listView.GridLines = $true
$listView.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
$listView.ForeColor = [System.Drawing.Color]::White
$listView.BorderStyle = "FixedSingle"
$listView.HeaderStyle = "Nonclickable"
$listView.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$listView.Columns.Add("Application", 160) | Out-Null
$listView.Columns.Add("Path", 390) | Out-Null
$form.Controls.Add($listView)

$btnUnblock = New-Object System.Windows.Forms.Button
$btnUnblock.Text = "✅  Unblock Selected"
$btnUnblock.Location = New-Object System.Drawing.Point(20, 420)
$btnUnblock.Size = New-Object System.Drawing.Size(275, 36)
$btnUnblock.FlatStyle = "Flat"
$btnUnblock.BackColor = [System.Drawing.Color]::FromArgb(40, 130, 70)
$btnUnblock.ForeColor = [System.Drawing.Color]::White
$btnUnblock.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnUnblock.Cursor = "Hand"
$form.Controls.Add($btnUnblock)

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "🔄  Refresh List"
$btnRefresh.Location = New-Object System.Drawing.Point(310, 420)
$btnRefresh.Size = New-Object System.Drawing.Size(275, 36)
$btnRefresh.FlatStyle = "Flat"
$btnRefresh.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$btnRefresh.ForeColor = [System.Drawing.Color]::White
$btnRefresh.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnRefresh.Cursor = "Hand"
$form.Controls.Add($btnRefresh)

# ── Firewall Status Panel ──────────────────────────────────────────────────────
$pnlFirewall = New-Object System.Windows.Forms.Panel
$pnlFirewall.Location = New-Object System.Drawing.Point(20, 468)
$pnlFirewall.Size = New-Object System.Drawing.Size(565, 46)
$form.Controls.Add($pnlFirewall)

$lblFirewall = New-Object System.Windows.Forms.Label
$lblFirewall.Location = New-Object System.Drawing.Point(10, 6)
$lblFirewall.Size = New-Object System.Drawing.Size(380, 34)
$lblFirewall.TextAlign = "MiddleLeft"
$lblFirewall.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$pnlFirewall.Controls.Add($lblFirewall)

$btnFirewall = New-Object System.Windows.Forms.Button
$btnFirewall.Text = "Turn On Firewall"
$btnFirewall.Location = New-Object System.Drawing.Point(400, 7)
$btnFirewall.Size = New-Object System.Drawing.Size(155, 32)
$btnFirewall.FlatStyle = "Flat"
$btnFirewall.BackColor = [System.Drawing.Color]::FromArgb(200, 120, 20)
$btnFirewall.ForeColor = [System.Drawing.Color]::White
$btnFirewall.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$btnFirewall.Cursor = "Hand"
$pnlFirewall.Controls.Add($btnFirewall)

# ── Status Bar ─────────────────────────────────────────────────────────────────
$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusBar.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(120, 200, 120)
$statusLabel.Text = "Ready - Running as Administrator"
$statusBar.Items.Add($statusLabel) | Out-Null
$form.Controls.Add($statusBar)

# ── Functions ──────────────────────────────────────────────────────────────────

function Update-FirewallStatus {
    $off = Get-FirewallState
    if ($off.Count -eq 0) {
        $pnlFirewall.BackColor = [System.Drawing.Color]::FromArgb(30, 70, 40)
        $lblFirewall.ForeColor = [System.Drawing.Color]::FromArgb(140, 230, 150)
        $lblFirewall.Text = "Windows Firewall: ON - blocks are active"
        $btnFirewall.Visible = $false
    }
    else {
        $pnlFirewall.BackColor = [System.Drawing.Color]::FromArgb(90, 30, 30)
        $lblFirewall.ForeColor = [System.Drawing.Color]::FromArgb(255, 170, 170)
        $lblFirewall.Text = "Windows Firewall is OFF ($($off -join ', ')).`nBlocks will NOT work until it is turned on."
        $btnFirewall.Visible = $true
    }
}

function Request-EnableFirewall {
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Turn on Windows Firewall for all network profiles (Domain, Private, Public)?`n`n" +
        "- Apps you have not blocked keep normal internet access.`n" +
        "- Unsolicited incoming connections (e.g. file sharing, remote access to this PC) " +
        "may be blocked unless they already have allow rules.",
        "Turn On Firewall", "YesNo", "Question"
    )
    if ($confirm -eq "Yes") {
        if (Enable-Firewall) {
            $statusLabel.Text = "Windows Firewall turned on"
        }
        Update-FirewallStatus
    }
}

function Refresh-List {
    $listView.Items.Clear()
    $blocked = Get-BlockedApps
    foreach ($app in $blocked) {
        $item = New-Object System.Windows.Forms.ListViewItem($app.Name)
        $item.SubItems.Add($app.Path) | Out-Null
        $item.Tag = $app.Name
        $listView.Items.Add($item) | Out-Null
    }
    $statusLabel.Text = "Showing $($blocked.Count) blocked app(s)"
    Update-FirewallStatus
}

# ── Event Handlers ─────────────────────────────────────────────────────────────

$btnBrowse.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Applications (*.exe)|*.exe|All Files (*.*)|*.*"
    $dialog.Title = "Select an application to block"
    $dialog.InitialDirectory = "C:\Program Files"
    if ($dialog.ShowDialog() -eq "OK") {
        $txtPath.Text = $dialog.FileName
    }
})

$btnBlock.Add_Click({
    if ([string]::IsNullOrWhiteSpace($txtPath.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please browse for an application first.",
            "No Application Selected",
            "OK", "Warning"
        )
        return
    }
    if (-not (Test-Path $txtPath.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "The selected file does not exist.",
            "File Not Found",
            "OK", "Error"
        )
        return
    }

    $exePath = $txtPath.Text
    $result = Block-Application -ExePath $exePath
    $statusLabel.Text = $result
    $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(120, 200, 120)
    Refresh-List
    $txtPath.Text = ""

    # Rules do nothing while the firewall is off
    if ((Get-FirewallState).Count -gt 0) {
        Request-EnableFirewall
    }

    # Already-open connections survive until the app restarts
    $appName = [System.IO.Path]::GetFileNameWithoutExtension($exePath)
    $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exePath })
    if ($running.Count -gt 0) {
        $close = [System.Windows.Forms.MessageBox]::Show(
            "'$appName' is currently running and may keep its existing connections until restarted.`n`n" +
            "Close it now? (Unsaved work in $appName will be lost.)",
            "Close Running App", "YesNo", "Question"
        )
        if ($close -eq "Yes") {
            $n = Stop-AppProcesses -ExePath $exePath
            $statusLabel.Text = "$result - closed $n process(es)"
        }
    }
})

$btnUnblock.Add_Click({
    if ($listView.SelectedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select an application to unblock.",
            "No Selection",
            "OK", "Warning"
        )
        return
    }

    $appName = $listView.SelectedItems[0].Tag
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Unblock '$appName' and allow internet access?",
        "Confirm Unblock",
        "YesNo", "Question"
    )
    if ($confirm -eq "Yes") {
        $result = Unblock-Application -AppName $appName
        $statusLabel.Text = $result
        $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(120, 200, 120)
        Refresh-List
    }
})

$btnRefresh.Add_Click({ Refresh-List })

$btnFirewall.Add_Click({ Request-EnableFirewall })

# Warn once on startup if the firewall is off
$form.Add_Shown({
    if ((Get-FirewallState).Count -gt 0) {
        Request-EnableFirewall
    }
})

# ── Initialize ─────────────────────────────────────────────────────────────────
Refresh-List

# ── Show Form ──────────────────────────────────────────────────────────────────
[System.Windows.Forms.Application]::Run($form)
