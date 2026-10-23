<#
.SYNOPSIS
    Read-only Active Directory hardening audit with PASS / FAIL / REVIEW / NOT TESTED results.

.DESCRIPTION
    Collects selected AD security and health evidence, highlights findings that violate
    the configurable baseline, and exports a CSV report. This script does not remediate
    or change Active Directory settings.

.NOTES
    Run only in an environment you are authorized to assess.
    Some checks require permissions, the ActiveDirectory and GroupPolicy modules, and
    PowerShell remoting access to Domain Controllers.

    IMPORTANT: The sample password baseline values below are examples, not universal
    requirements. Set them to your organization's approved security baseline before
    interpreting FAIL results as compliance violations.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = '',
    [int]$InactiveDays = 90,
    [int]$EventLookbackHours = 24,
    [switch]$SkipRemoteChecks,
    [switch]$SkipSecurityEventReview
)

# -----------------------------------------------------------------------------
# CONFIGURATION: customize these values before using this script for compliance.
# -----------------------------------------------------------------------------
$Baseline = @{
    # Illustrative values only. Align these with your formally approved baseline.
    MinPasswordLength       = 14
    MinPasswordHistoryCount = 24
    RequireComplexity       = $true

    # Leave $null to record this as a manual review item rather than enforce a value.
    # If configured, the observed threshold must exactly match the approved value.
    ExpectedLockoutThreshold = $null

    # If true, SMBv1 being enabled on an assessed Domain Controller is a Critical FAIL.
    Smb1MustBeDisabled      = $true
}

# Populate each list with the accounts specifically approved for that group.
# Leave a group absent / empty until you have an authoritative approved-membership list.
# Without a configured list, membership is REVIEW, not an automatic FAIL.
$ApprovedPrivilegedAccountsByGroup = @{
    # Examples (replace with approved sAMAccountNames from your own environment):
    # 'Domain Admins'              = @('alice.admin')
    # 'Enterprise Admins'          = @('alice.admin')
    # 'Schema Admins'               = @('forest.admin')
    # 'Administrators'              = @('tier0.admin')
    # 'Account Operators'           = @()
    # 'Server Operators'            = @()
    # 'Print Operators'             = @()
    # 'Backup Operators'            = @()
    # 'Group Policy Creator Owners' = @('gpo.admin')
}

$script:AuditResults = @()
$script:AuditStart = Get-Date
$ErrorActionPreference = 'Stop'

function Add-AuditResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Control,
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL','REVIEW','NOT TESTED')][string]$Status,
        [Parameter(Mandatory)][ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO')][string]$Severity,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$Recommendation,
        [string]$Target = 'Domain'
    )

    $script:AuditResults += [pscustomobject]@{
        CheckedAt      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Target         = $Target
        Control        = $Control
        Status         = $Status
        Severity       = $Severity
        Evidence       = ($Evidence -replace '[\r\n]+', ' ').Trim()
        Recommendation = ($Recommendation -replace '[\r\n]+', ' ').Trim()
    }
}

function Limit-Text {
    param([string]$Text, [int]$MaxLength = 350)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '(no additional details)' }
    $singleLine = ($Text -replace '[\r\n]+', ' ').Trim()
    if ($singleLine.Length -gt $MaxLength) { return $singleLine.Substring(0, $MaxLength) + '...' }
    return $singleLine
}

function Test-Threshold {
    param(
        [string]$Control,
        [double]$Actual,
        [double]$Minimum,
        [string]$Unit
    )
    if ($Actual -ge $Minimum) {
        Add-AuditResult -Control $Control -Status PASS -Severity INFO `
            -Evidence ("Observed {0}; configured minimum is {1} {2}." -f $Actual, $Minimum, $Unit) `
            -Recommendation 'No action indicated by this threshold check.'
    }
    else {
        Add-AuditResult -Control $Control -Status FAIL -Severity HIGH `
            -Evidence ("Observed {0}; configured minimum is {1} {2}." -f $Actual, $Minimum, $Unit) `
            -Recommendation 'Validate the approved baseline and plan any required change through the normal change-control process.'
    }
}

Write-Host ''
Write-Host 'Active Directory Hardening Audit (read-only)' -ForegroundColor Cyan
Write-Host ('Started: {0}' -f $script:AuditStart.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host 'No configuration changes or remediation actions will be performed.' -ForegroundColor DarkGray
Write-Host ''

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
}
catch {
    Write-Error ("Could not initialize Active Directory checks. Ensure the ActiveDirectory module is installed and you have read access. Details: {0}" -f $_.Exception.Message)
    throw
}

$domainSid = $domain.DomainSID.Value
$domainName = $domain.DNSRoot
Write-Host ("Domain: {0}" -f $domainName) -ForegroundColor Cyan

# Set a useful default report location. If this script is under /checks, use ../reports.
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $parentDir = Split-Path -Parent $PSScriptRoot
    if ((Split-Path -Leaf $PSScriptRoot) -ieq 'checks') {
        $OutputDirectory = Join-Path $parentDir 'reports'
    }
    else {
        $OutputDirectory = Join-Path $PSScriptRoot 'reports'
    }
}

# 1) Default domain password policy
try {
    $pwdPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    Test-Threshold -Control 'Password policy - minimum length' `
        -Actual ([double]$pwdPolicy.MinPasswordLength) `
        -Minimum ([double]$Baseline.MinPasswordLength) -Unit 'characters'

    Test-Threshold -Control 'Password policy - password history' `
        -Actual ([double]$pwdPolicy.PasswordHistoryCount) `
        -Minimum ([double]$Baseline.MinPasswordHistoryCount) -Unit 'previous passwords'

    if ([bool]$pwdPolicy.ComplexityEnabled) {
        Add-AuditResult -Control 'Password policy - complexity' -Status PASS -Severity INFO `
            -Evidence ("Password complexity is enabled; configured requirement is {0}." -f $Baseline.RequireComplexity) `
            -Recommendation 'No action indicated by this check.'
    }
    elseif ($Baseline.RequireComplexity) {
        Add-AuditResult -Control 'Password policy - complexity' -Status FAIL -Severity HIGH `
            -Evidence 'Password complexity is disabled but the configured baseline requires it.' `
            -Recommendation 'Review the approved password standard and apply changes only through change control.'
    }
    else {
        Add-AuditResult -Control 'Password policy - complexity' -Status REVIEW -Severity MEDIUM `
            -Evidence 'Password complexity is disabled; this script is not configured to require it, so verify the approved policy and compensating controls.' `
            -Recommendation 'Confirm the organization's approved password requirements, including any applicable fine-grained policies.'
    }

    if ($null -ne $Baseline.ExpectedLockoutThreshold) {
        if ([int]$pwdPolicy.LockoutThreshold -eq [int]$Baseline.ExpectedLockoutThreshold) {
            Add-AuditResult -Control 'Password policy - account lockout threshold' -Status PASS -Severity INFO `
                -Evidence ("Observed threshold {0} matches configured expected value {1}." -f $pwdPolicy.LockoutThreshold, $Baseline.ExpectedLockoutThreshold) `
                -Recommendation 'No action indicated by this comparison.'
        }
        else {
            Add-AuditResult -Control 'Password policy - account lockout threshold' -Status FAIL -Severity HIGH `
                -Evidence ("Observed threshold {0}; configured expected value is {1}." -f $pwdPolicy.LockoutThreshold, $Baseline.ExpectedLockoutThreshold) `
                -Recommendation 'Validate the approved baseline and review lockout behavior before making any configuration change.'
        }
    }
    else {
        Add-AuditResult -Control 'Password policy - account lockout threshold' -Status REVIEW -Severity MEDIUM `
            -Evidence ("Observed lockout threshold: {0}; no approved comparison threshold is configured in this script." -f $pwdPolicy.LockoutThreshold) `
            -Recommendation 'Compare lockout threshold, duration, and reset-window settings with the approved organizational standard.'
    }
}
catch {
    Add-AuditResult -Control 'Default domain password policy' -Status 'NOT TESTED' -Severity HIGH `
        -Evidence (Limit-Text $_.Exception.Message) `
        -Recommendation 'Check Active Directory permissions and confirm the default domain password policy can be read.'
}

# 2) Privileged group membership. Uses well-known SIDs to avoid localized group names.
$privilegedGroups = @(
    [pscustomobject]@{ Key='Domain Admins';              SID=("{0}-512" -f $domainSid) },
    [pscustomobject]@{ Key='Schema Admins';               SID=("{0}-518" -f $domainSid) },
    [pscustomobject]@{ Key='Enterprise Admins';           SID=("{0}-519" -f $domainSid) },
    [pscustomobject]@{ Key='Group Policy Creator Owners'; SID=("{0}-520" -f $domainSid) },
    [pscustomobject]@{ Key='Administrators';              SID='S-1-5-32-544' },
    [pscustomobject]@{ Key='Account Operators';           SID='S-1-5-32-548' },
    [pscustomobject]@{ Key='Server Operators';            SID='S-1-5-32-549' },
    [pscustomobject]@{ Key='Print Operators';             SID='S-1-5-32-550' },
    [pscustomobject]@{ Key='Backup Operators';            SID='S-1-5-32-551' }
)
$allPrivilegedSamNames = @()

foreach ($privGroup in $privilegedGroups) {
    try {
        $group = Get-ADGroup -Identity $privGroup.SID -ErrorAction Stop
        $members = @(Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction Stop)
        $memberNames = @($members | Where-Object { -not [string]::IsNullOrWhiteSpace($_.SamAccountName) } | ForEach-Object { $_.SamAccountName })
        $allPrivilegedSamNames += $memberNames

        $approvedList = $ApprovedPrivilegedAccountsByGroup[$privGroup.Key]
        if ($null -eq $approvedList) {
            Add-AuditResult -Control ("Privileged membership - {0}" -f $privGroup.Key) -Status REVIEW -Severity HIGH `
                -Evidence ("Found {0} recursive member(s). No approved membership list is configured for this group." -f $members.Count) `
                -Recommendation 'Compare members with an authoritative, group-specific approved access list and document exceptions.' `
                -Target $privGroup.Key
        }
        else {
            $unexpected = @($memberNames | Where-Object { $approvedList -notcontains $_ })
            if ($unexpected.Count -gt 0) {
                $shown = ($unexpected | Select-Object -First 10) -join ', '
                Add-AuditResult -Control ("Privileged membership - {0}" -f $privGroup.Key) -Status FAIL -Severity CRITICAL `
                    -Evidence ("Found {0} member(s) not present in the configured allow-list: {1}{2}" -f $unexpected.Count, $shown, $(if ($unexpected.Count -gt 10) { ', ...' } else { '' })) `
                    -Recommendation 'Validate each unexpected member urgently. Remove access only after confirming the approved access process and obtaining required authorization.' `
                    -Target $privGroup.Key
            }
            else {
                Add-AuditResult -Control ("Privileged membership - {0}" -f $privGroup.Key) -Status PASS -Severity INFO `
                    -Evidence ("All {0} recursive member(s) matched the configured allow-list." -f $members.Count) `
                    -Recommendation 'Keep the allow-list current and periodically revalidate business justification.' `
                    -Target $privGroup.Key
            }
        }
    }
    catch {
        Add-AuditResult -Control ("Privileged membership - {0}" -f $privGroup.Key) -Status 'NOT TESTED' -Severity HIGH `
            -Evidence (Limit-Text $_.Exception.Message) `
            -Recommendation 'Verify that the group exists in this domain and that your account can read its recursive membership.' `
            -Target $privGroup.Key
    }
}
$allPrivilegedSamNames = @($allPrivilegedSamNames | Sort-Object -Unique)

# 3) Enabled inactive user accounts
try {
    $inactiveUsers = @(Search-ADAccount -AccountInactive -UsersOnly -TimeSpan (New-TimeSpan -Days $InactiveDays) -ErrorAction Stop |
        Where-Object { $_.Enabled })

    if ($inactiveUsers.Count -eq 0) {
        Add-AuditResult -Control 'Account lifecycle - inactive enabled users' -Status PASS -Severity INFO `
            -Evidence ("No enabled users were returned by the {0}-day inactivity query." -f $InactiveDays) `
            -Recommendation 'Confirm the search scope and account activity sources are appropriate for your environment.'
    }
    else {
        foreach ($user in $inactiveUsers) {
            $isPrivileged = $allPrivilegedSamNames -contains $user.SamAccountName
            $severity = if ($isPrivileged) { 'HIGH' } else { 'MEDIUM' }
            Add-AuditResult -Control 'Account lifecycle - inactive enabled user' -Status REVIEW -Severity $severity `
                -Evidence ("Account {0}; Enabled={1}; LastLogonDate={2}; inactivity query={3} days." -f $user.SamAccountName, $user.Enabled, $user.LastLogonDate, $InactiveDays) `
                -Recommendation 'Validate the owner, employment or service status, and recent activity before considering a disablement.' `
                -Target $user.SamAccountName
        }
    }
}
catch {
    Add-AuditResult -Control 'Account lifecycle - inactive enabled users' -Status 'NOT TESTED' -Severity MEDIUM `
        -Evidence (Limit-Text $_.Exception.Message) `
        -Recommendation 'Check query permissions and confirm the inactivity interval is appropriate.'
}

# 4) Enabled accounts with PasswordNeverExpires
try {
    $neverExpireUsers = @(Get-ADUser -Filter 'Enabled -eq $true -and PasswordNeverExpires -eq $true' `
        -Properties Enabled, PasswordNeverExpires -ErrorAction Stop)

    if ($neverExpireUsers.Count -eq 0) {
        Add-AuditResult -Control 'Credential management - PasswordNeverExpires' -Status PASS -Severity INFO `
            -Evidence 'No enabled users matched PasswordNeverExpires=True.' `
            -Recommendation 'Continue periodic credential-policy review and validate service-account requirements.'
    }
    else {
        foreach ($user in $neverExpireUsers) {
            $isPrivileged = $allPrivilegedSamNames -contains $user.SamAccountName
            $severity = if ($isPrivileged) { 'HIGH' } else { 'MEDIUM' }
            Add-AuditResult -Control 'Credential management - PasswordNeverExpires' -Status REVIEW -Severity $severity `
                -Evidence ("Enabled account {0} has PasswordNeverExpires=True." -f $user.SamAccountName) `
                -Recommendation 'Verify the documented exception and assess managed service accounts, credential rotation, and compensating controls.' `
                -Target $user.SamAccountName
        }
    }
}
catch {
    Add-AuditResult -Control 'Credential management - PasswordNeverExpires' -Status 'NOT TESTED' -Severity MEDIUM `
        -Evidence (Limit-Text $_.Exception.Message) `
        -Recommendation 'Check directory read permissions and confirm the required attributes are available.'
}

# 5) Domain Controller inventory and optional remote SMBv1 check
try {
    $domainControllers = @(Get-ADDomainController -Filter * -ErrorAction Stop)
    Add-AuditResult -Control 'Domain Controller inventory' -Status REVIEW -Severity MEDIUM `
        -Evidence ("Discovered {0} Domain Controller(s); each OS and site should be reconciled with the approved asset and support-lifecycle inventory." -f $domainControllers.Count) `
        -Recommendation 'Validate each controller, operating-system support status, patch level, site, and approved exception.'

    foreach ($dc in $domainControllers) {
        Add-AuditResult -Control 'Domain Controller OS inventory' -Status REVIEW -Severity MEDIUM `
            -Evidence ("OS={0}; Site={1}. Support lifecycle and patch compliance were not verified by this query." -f $dc.OperatingSystem, $dc.Site) `
            -Recommendation 'Compare the reported OS with the organization's supported-platform and patching standards.' `
            -Target $dc.HostName

        if ($SkipRemoteChecks) {
            Add-AuditResult -Control 'SMBv1 configuration' -Status 'NOT TESTED' -Severity HIGH `
                -Evidence 'Remote checks were skipped by the -SkipRemoteChecks switch.' `
                -Recommendation 'Run an authorized host-level check on this Domain Controller.' `
                -Target $dc.HostName
        }
        else {
            try {
                $smbConfig = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                    Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol
                } -ErrorAction Stop

                if ([bool]$smbConfig.EnableSMB1Protocol -and $Baseline.Smb1MustBeDisabled) {
                    Add-AuditResult -Control 'SMBv1 configuration' -Status FAIL -Severity CRITICAL `
                        -Evidence 'SMBv1 is enabled on this Domain Controller and the configured baseline requires it to be disabled.' `
                        -Recommendation 'Validate legacy dependencies and plan disabling SMBv1 through an approved change process.' `
                        -Target $dc.HostName
                }
                elseif ([bool]$smbConfig.EnableSMB1Protocol) {
                    Add-AuditResult -Control 'SMBv1 configuration' -Status REVIEW -Severity HIGH `
                        -Evidence 'SMBv1 is enabled; this script is not configured to enforce an SMBv1 prohibition.' `
                        -Recommendation 'Review the organization's protocol baseline and any documented dependencies.' `
                        -Target $dc.HostName
                }
                else {
                    Add-AuditResult -Control 'SMBv1 configuration' -Status PASS -Severity INFO `
                        -Evidence ("SMBv1 disabled. SMBv2/SMBv3 protocol setting reported as {0}." -f $smbConfig.EnableSMB2Protocol) `
                        -Recommendation 'No SMBv1 action indicated by this check.' `
                        -Target $dc.HostName
                }
            }
            catch {
                Add-AuditResult -Control 'SMBv1 configuration' -Status 'NOT TESTED' -Severity HIGH `
                    -Evidence (Limit-Text $_.Exception.Message) `
                    -Recommendation 'Check PowerShell remoting, host reachability, permissions, and availability of Get-SmbServerConfiguration.' `
                    -Target $dc.HostName
            }
        }
    }
}
catch {
    Add-AuditResult -Control 'Domain Controller inventory' -Status 'NOT TESTED' -Severity HIGH `
        -Evidence (Limit-Text $_.Exception.Message) `
        -Recommendation 'Confirm Domain Controller discovery permissions and Active Directory connectivity.'
    $domainControllers = @()
}

# 6) Group Policy inventory; an inventory alone does not prove effective policy.
try {
    Import-Module GroupPolicy -ErrorAction Stop
    $gpos = @(Get-GPO -All -ErrorAction Stop)
    Add-AuditResult -Control 'Group Policy inventory' -Status REVIEW -Severity MEDIUM `
        -Evidence ("Found {0} GPO(s). Links, filtering, inheritance, and resultant policy were not validated by this inventory." -f $gpos.Count) `
        -Recommendation 'Compare GPOs with the approved inventory and verify effective policy on in-scope systems.'

    foreach ($gpo in $gpos) {
        if ([string]$gpo.GpoStatus -match 'AllSettingsDisabled|UserSettingsDisabled|ComputerSettingsDisabled') {
            Add-AuditResult -Control 'Group Policy - disabled settings' -Status REVIEW -Severity MEDIUM `
                -Evidence ("GPO '{0}' has status {1}; modified {2}." -f $gpo.DisplayName, $gpo.GpoStatus, $gpo.ModificationTime) `
                -Recommendation 'Confirm the disabled portion is intentional and that required settings are provided elsewhere.' `
                -Target $gpo.DisplayName
        }
    }
}
catch {
    Add-AuditResult -Control 'Group Policy inventory' -Status 'NOT TESTED' -Severity MEDIUM `
        -Evidence (Limit-Text $_.Exception.Message) `
        -Recommendation 'Install or import the GroupPolicy module and confirm GPO read permissions.'
}

# 7) Replication health. Failures are REVIEW operational/security-integrity signals, not proof of compromise.
if ($domainControllers.Count -gt 0) {
    $replicationFailures = @()
    $replicationQueryErrors = @()
    foreach ($dc in $domainControllers) {
        try {
            $replicationFailures += @(Get-ADReplicationFailure -Target $dc.HostName -Scope Server -ErrorAction Stop)
        }
        catch {
            $replicationQueryErrors += ("{0}: {1}" -f $dc.HostName, (Limit-Text $_.Exception.Message 180))
        }
    }

    if ($replicationQueryErrors.Count -gt 0) {
        Add-AuditResult -Control 'Active Directory replication health' -Status 'NOT TESTED' -Severity HIGH `
            -Evidence ("Replication query errors: {0}" -f (($replicationQueryErrors | Select-Object -First 3) -join ' | ')) `
            -Recommendation 'Resolve query/permission issues, then review replication health for every Domain Controller.'
    }
    elseif ($replicationFailures.Count -gt 0) {
        $sampleFailures = @($replicationFailures | Select-Object -First 5 | ForEach-Object {
            "{0}: {1}" -f $_.Server, $_.Failure
        }) -join '; '
        Add-AuditResult -Control 'Active Directory replication health' -Status REVIEW -Severity HIGH `
            -Evidence ("Detected {0} replication failure record(s). Examples: {1}" -f $replicationFailures.Count, $sampleFailures) `
            -Recommendation 'Investigate the specific replication errors and confirm successful replication after remediation.'
    }
    else {
        Add-AuditResult -Control 'Active Directory replication health' -Status PASS -Severity INFO `
            -Evidence 'No replication failure records were returned for the queried Domain Controllers.' `
            -Recommendation 'Continue monitoring replication and review directory health as part of routine operations.'
    }
}
else {
    Add-AuditResult -Control 'Active Directory replication health' -Status 'NOT TESTED' -Severity HIGH `
        -Evidence 'No Domain Controllers were available to query.' `
        -Recommendation 'Resolve Domain Controller discovery before assessing replication health.'
}

# 8) Security event sampling on each DC. Events are leads for investigation, not proof of malice.
if ($SkipSecurityEventReview) {
    Add-AuditResult -Control 'Security event review' -Status 'NOT TESTED' -Severity MEDIUM `
        -Evidence 'Skipped by -SkipSecurityEventReview.' `
        -Recommendation 'Review the Security log under an approved audit scope if required.'
}
elseif ($SkipRemoteChecks) {
    Add-AuditResult -Control 'Security event review' -Status 'NOT TESTED' -Severity MEDIUM `
        -Evidence 'Remote checks were skipped, so Security logs on Domain Controllers were not queried.' `
        -Recommendation 'Run an authorized event-log review or repeat without -SkipRemoteChecks.'
}
elseif ($domainControllers.Count -gt 0) {
    $eventQueryErrors = @()
    $eventFindings = @()
    foreach ($dc in $domainControllers) {
        try {
            $dcEvents = @(Invoke-Command -ComputerName $dc.HostName -ArgumentList $EventLookbackHours -ScriptBlock {
                param($hours)
                try {
                    Get-WinEvent -FilterHashtable @{
                        LogName = 'Security'
                        Id = 4720, 4728, 4732, 1102
                        StartTime = (Get-Date).AddHours((-1) * [int]$hours)
                    } -MaxEvents 100 -ErrorAction Stop |
                        Select-Object Id, TimeCreated, MachineName
                }
                catch {
                    if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') { return @() }
                    throw
                }
            } -ErrorAction Stop)
            foreach ($event in $dcEvents) {
                $eventFindings += [pscustomobject]@{
                    DC = $dc.HostName
                    Id = $event.Id
                    TimeCreated = $event.TimeCreated
                }
            }
        }
        catch {
            $eventQueryErrors += ("{0}: {1}" -f $dc.HostName, (Limit-Text $_.Exception.Message 180))
        }
    }

    if ($eventQueryErrors.Count -gt 0) {
        Add-AuditResult -Control 'Security event review' -Status 'NOT TESTED' -Severity MEDIUM `
            -Evidence ("Could not query all requested Security logs: {0}" -f (($eventQueryErrors | Select-Object -First 3) -join ' | ')) `
            -Recommendation 'Check Security-log permissions, remote connectivity, audit policy, and log retention; note any gaps in the report.'
    }
    elseif ($eventFindings.Count -gt 0) {
        $eventSummary = @($eventFindings | Group-Object Id | ForEach-Object { "Event ID {0}: {1}" -f $_.Name, $_.Count }) -join '; '
        Add-AuditResult -Control 'Security event review' -Status REVIEW -Severity HIGH `
            -Evidence ("Found {0} sampled event(s) in the previous {1} hour(s): {2}" -f $eventFindings.Count, $EventLookbackHours, $eventSummary) `
            -Recommendation 'Inspect full event details and correlate affected accounts/groups with authorized change records. Event IDs alone do not prove malicious activity.'
    }
    else {
        Add-AuditResult -Control 'Security event review' -Status REVIEW -Severity LOW `
            -Evidence ("No matching events were returned in the previous {0} hour(s); log completeness and audit-policy coverage were not verified." -f $EventLookbackHours) `
            -Recommendation 'Confirm audit policy, Security-log retention, and that all relevant Domain Controllers were queried.'
    }
}
else {
    Add-AuditResult -Control 'Security event review' -Status 'NOT TESTED' -Severity MEDIUM `
        -Evidence 'No Domain Controllers were available to query.' `
        -Recommendation 'Resolve Domain Controller discovery before reviewing domain security events.'
}

# 9) Export and summarize
try {
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $reportPath = Join-Path $OutputDirectory ("AD-Hardening-Audit-{0}.csv" -f $timestamp)
    $script:AuditResults | Export-Csv -LiteralPath $reportPath -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Warning ("Could not export the CSV report: {0}" -f $_.Exception.Message)
    $reportPath = $null
}

Write-Host ''
Write-Host 'AUDIT RESULTS' -ForegroundColor Cyan
$script:AuditResults |
    Sort-Object @{Expression={
        switch ($_.Severity) {
            'CRITICAL' { 0 }
            'HIGH'     { 1 }
            'MEDIUM'   { 2 }
            'LOW'      { 3 }
            default    { 4 }
        }
    }}, @{Expression={ $_.Status }} |
    Format-Table -Property Status, Severity, Control, Target, Evidence -AutoSize -Wrap

$criticalCount = @($script:AuditResults | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'CRITICAL' }).Count
$failCount = @($script:AuditResults | Where-Object { $_.Status -eq 'FAIL' }).Count
$reviewCount = @($script:AuditResults | Where-Object { $_.Status -eq 'REVIEW' }).Count
$passCount = @($script:AuditResults | Where-Object { $_.Status -eq 'PASS' }).Count
$notTestedCount = @($script:AuditResults | Where-Object { $_.Status -eq 'NOT TESTED' }).Count

Write-Host ''
Write-Host 'SUMMARY' -ForegroundColor Cyan
Write-Host ("Domain:           {0}" -f $domainName)
Write-Host ("Controls/results: {0}" -f $script:AuditResults.Count)
Write-Host ("PASS:             {0}" -f $passCount) -ForegroundColor Green
Write-Host ("FAIL:             {0}" -f $failCount) -ForegroundColor Red
Write-Host ("CRITICAL FAIL:    {0}" -f $criticalCount) -ForegroundColor Red
Write-Host ("REVIEW:           {0}" -f $reviewCount) -ForegroundColor Yellow
Write-Host ("NOT TESTED:       {0}" -f $notTestedCount) -ForegroundColor DarkYellow
if ($reportPath) {
    Write-Host ("CSV report:       {0}" -f $reportPath) -ForegroundColor Cyan
}
Write-Host ''
Write-Host 'Interpretation:' -ForegroundColor Cyan
Write-Host '- PASS means the observed setting met the configured check; it is not a guarantee of overall security.'
Write-Host '- FAIL means the observed setting violated a configured baseline or privileged-access allow-list.'
Write-Host '- REVIEW means a human must validate context, exceptions, effective policy, or operational signals.'
Write-Host '- NOT TESTED means a check could not be completed; do not treat it as PASS.'
Write-Host '- Change the example baseline and configure approved privileged-group lists before using results as compliance evidence.' -ForegroundColor Yellow
