# Active Directory Hardening Audit

A read-only PowerShell checklist for manual Active Directory hardening audits, security configuration reviews, and organizational audit evidence collection.

## Overview

This project helps system administrators, security engineers, and auditors review selected Active Directory security configurations and identify areas that may require further investigation.

The repository includes PowerShell audit checks, example findings, and guidance for interpreting results against an organization's approved security baseline.

**This project is designed for auditing, not automatic remediation.** It does not make configuration changes to Active Directory or domain systems.

## Objectives

- Review privileged group membership.
- Inspect password and account security settings.
- Identify potentially inactive or unnecessary accounts.
- Review Domain Controller inventory and operating systems.
- Check selected legacy protocol configurations.
- Review Group Policy Objects (GPOs).
- Check Active Directory replication health.
- Examine selected Windows security events.
- Document evidence and potential security findings.

## Requirements

- Windows PowerShell or a compatible PowerShell environment.
- Appropriate read permissions for the Active Directory objects being reviewed.
- The Active Directory PowerShell module for AD-related commands.
- Administrative or delegated permissions where required to inspect specific systems or logs.
- Access to the relevant Domain Controllers when performing host-specific checks.

Some checks require additional modules, local access, or permissions. A failed command may indicate a permissions issue, unavailable module, connectivity problem, or unsupported environment rather than a confirmed security weakness.


Open PowerShell in an environment with the required modules and permissions.

Review the commands before execution. Run only the checks appropriate for your authorized assessment scope.

Example:

```powershell
Import-Module ActiveDirectory

Get-ADDomain
Get-ADDefaultDomainPasswordPolicy

Get-ADGroupMember "Domain Admins" -Recursive |
    Select-Object Name, SamAccountName, ObjectClass
```

Run checks individually when possible so you can confirm their scope, understand the output, and retain relevant evidence.

## Audit Checks

The following commands illustrate the types of checks included in this project. Their outputs should be compared with the organization's approved baseline and documented requirements.

### 1. Privileged Group Membership

```powershell
Get-ADGroupMember "Domain Admins" -Recursive |
    Select-Object Name, SamAccountName, ObjectClass
```

**What to look for:**

- Accounts that are not on the approved privileged-access list.
- Service accounts with domain-level administrative privileges.
- Unexpected nested group membership.
- Accounts that no longer require administrative access.

Membership alone does not prove that an account is unauthorized. Verify the account owner, business purpose, and approved access requirements.

### 2. Password Policy

```powershell
Get-ADDefaultDomainPasswordPolicy |
    Select-Object MinPasswordLength,
        PasswordHistoryCount,
        ComplexityEnabled,
        LockoutThreshold
```

**What to look for:**

- Settings that do not meet the approved organizational baseline.
- Account lockout settings that are missing or inconsistent with policy.
- Differences between the default domain policy and applicable Fine-Grained Password Policies.

The default domain policy does not necessarily describe the effective password policy for every user. Review applicable fine-grained policies when relevant.

### 3. Inactive Accounts

```powershell
Search-ADAccount -AccountInactive `
    -UsersOnly `
    -TimeSpan 90.00:00:00 |
    Select-Object Name, SamAccountName, Enabled, LastLogonDate
```

**What to look for:**

- Enabled accounts with no recent recorded activity.
- Former employees whose accounts remain enabled.
- Dormant privileged accounts.
- Accounts without an identifiable owner.

`LastLogonDate` is approximate. Missing or old logon information does not, by itself, prove that an account is unused.

### 4. Passwords Never Expire

```powershell
Get-ADUser -Filter 'PasswordNeverExpires -eq $true' `
    -Properties Enabled |
    Where-Object Enabled |
    Select-Object Name, SamAccountName
```

**What to look for:**

- Privileged accounts with undocumented exceptions.
- Service accounts without a documented credential-management process.
- Accounts whose credentials have not been reviewed according to policy.

This attribute alone does not establish a security violation. Validate the account's purpose and applicable credential-management requirements.

### 5. Domain Controller Inventory

```powershell
Get-ADDomainController -Filter * |
    Select-Object HostName, OperatingSystem, Site
```

**What to look for:**

- Operating systems outside their supported lifecycle.
- Unexpected or undocumented Domain Controllers.
- Missing Domain Controllers or incorrect site placement.
- Differences between the AD inventory and the organization's asset register.

Verify the actual support lifecycle, patch status, and any approved extended-support arrangements before recording a finding.

### 6. SMB Configuration

```powershell
Get-SmbServerConfiguration |
    Select-Object EnableSMB1Protocol, EnableSMB2Protocol
```

**What to look for:**

- SMBv1 enabled on systems where the approved baseline prohibits it.
- Legacy dependencies that have not been documented.
- Differences between the configuration of individual systems.

This command checks the local system on which it runs. It does not automatically inspect every Domain Controller. Use an authorized method to assess each in-scope host.

### 7. Group Policy Review

```powershell
Get-GPO -All |
    Select-Object DisplayName, GpoStatus, ModificationTime
```

**What to look for:**

- Security GPOs that are disabled or incorrectly scoped.
- Unexpected changes to sensitive policies.
- Missing security settings on Domain Controllers or other critical systems.
- GPOs that exist but are not applied to the intended computers.

The existence of a GPO does not prove that its settings are effective. Review links, security filtering, inheritance, and resultant policy. A disabled GPO is not automatically a violation.

### 8. Active Directory Replication

```powershell
repadmin /replsummary
```

**What to look for:**

- Nonzero replication failures.
- Increasing replication delays.
- Errors involving DNS, connectivity, authentication, or replication permissions.

Replication failures are operational warnings that require investigation. They are not, by themselves, proof of a security breach.

### 9. Security Event Review

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4720, 4728, 4732, 1102
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 50 |
    Select-Object TimeCreated, Id, MachineName, Message
```

**What to look for:**

- Unexpected user account creation.
- Unapproved additions to security groups.
- Security log clearing without an authorized explanation.
- Activity outside approved change windows.

The event ID alone does not establish malicious activity. Inspect the full event details, affected objects, relevant timestamps, and approved change records. Ensure the relevant audit policies are enabled and that the required logs are available.

## Interpreting Audit Results

Use the following status labels consistently.

| Status | Meaning |
|---|---|
| `PASS` | Evidence demonstrates that the control meets the applicable approved requirement. |
| `FAIL` | Evidence demonstrates that the control does not meet an applicable approved requirement. |
| `REVIEW` | The evidence requires validation, contextual analysis, or manual investigation. |
| `NOT TESTED` | The check could not be completed or was outside the assessment scope. |

A check should not be marked `FAIL` merely because a setting looks weak or unusual. Identify the applicable requirement and confirm the evidence before assigning a final result.

---

## Sample Audit Output and What to Look For

**All hostnames, domain names, account names, and values in this section are fictional.** The examples demonstrate how an auditor might document potential findings. They do not describe a real environment or define universal security requirements.

### Example 1: Privileged Group Membership

**Example output**

```text
Name                  SamAccountName       ObjectClass
----                  --------------       -----------
Alice Admin           alice.admin          user
Bob Service           svc-backup           user
DC01                  DC01$                computer
```

**Potential finding**

```text
Finding ID: AD-001
Category: Privileged Access
Status: REVIEW
Evidence: svc-backup is a member of Domain Admins.
Risk: Excessive privileges may increase the impact of a compromised service account.
Recommendation: Verify business justification and compare the account with the approved access list.
```

**Auditor's interpretation:** Determine whether the service account has an approved need for domain-level privileges. Do not classify it as unauthorized until the relevant access requirements and exceptions have been checked.

### Example 2: Password Policy

**Example output**

```text
MinPasswordLength    : 8
PasswordHistoryCount : 5
ComplexityEnabled    : True
LockoutThreshold     : 0
```

**Potential finding**

```text
Finding ID: AD-002
Category: Password Policy
Status: FAIL
Evidence: Minimum password length is 8; the approved audit baseline requires 14.
Risk: Password policy may not meet the organization's minimum requirements.
Recommendation: Review the policy and plan an approved configuration change.
```

**Auditor's interpretation:** This example is a `FAIL` only because the hypothetical approved baseline requires a minimum length of 14. That value is illustrative, not a universal requirement. Review lockout settings and applicable Fine-Grained Password Policies as well.

### Example 3: Inactive Accounts

**Example output**

```text
Name             SamAccountName    Enabled    LastLogonDate
----             --------------    -------    -------------
Former Employee  former.employee   True       2026-04-01
Test Account     test.account      True
```

**Potential finding**

```text
Finding ID: AD-003
Category: Account Lifecycle
Status: REVIEW
Evidence: former.employee is enabled and has an old recorded logon date.
Risk: An unnecessary active account may provide an additional path for unauthorized access.
Recommendation: Validate employment status, account ownership, and recent sign-in records.
```

**Auditor's interpretation:** Confirm the account's owner, employment or operational status, and activity. Do not disable an account solely because it appears in this output.

### Example 4: Passwords Never Expire

**Example output**

```text
Name              SamAccountName
----              --------------
Legacy Admin      legacy.admin
Backup Service    svc.backup
```

**Potential finding**

```text
Finding ID: AD-004
Category: Credential Management
Status: REVIEW
Evidence: legacy.admin has PasswordNeverExpires enabled.
Risk: An exception without appropriate controls may increase credential exposure.
Recommendation: Verify the exception and assess suitable credential rotation or managed-account controls.
```

**Auditor's interpretation:** Check whether the exception is approved and whether appropriate credential-management controls are in place. The attribute alone does not establish a violation.

### Example 5: Domain Controller Inventory

**Example output**

```text
HostName       OperatingSystem                  Site
--------       ---------------                  ----
DC01.example   Windows Server 2022 Standard     HQ
DC02.example   Windows Server 2012 R2 Standard  Branch
```

**Potential finding**

```text
Finding ID: AD-005
Category: Domain Controller Security
Status: REVIEW
Evidence: DC02 reports Windows Server 2012 R2.
Risk: The operating system may be outside its normal support lifecycle.
Recommendation: Verify edition, extended support entitlement, patch status, and approved exceptions.
```

**Auditor's interpretation:** Validate the operating system's actual support status and patching arrangements before deciding whether the system violates the organization's requirements.

### Example 6: SMBv1 Configuration

**Example output**

```text
EnableSMB1Protocol EnableSMB2Protocol
------------------ ------------------
True               True
```

**Potential finding**

```text
Finding ID: AD-006
Category: Legacy Protocols
Status: FAIL
Evidence: SMBv1 is enabled on DC01.
Risk: The legacy protocol may increase exposure to known SMB-related security threats.
Recommendation: Validate dependencies and disable SMBv1 through an approved change process.
```

**Auditor's interpretation:** This example assumes the approved baseline prohibits SMBv1. Confirm the host name and actual configuration. The command checks the local system, not the entire domain.

### Example 7: Group Policy Review

**Example output**

```text
DisplayName                 GpoStatus                 ModificationTime
-----------                 ---------                 ---------------
Default Domain Policy       AllSettingsEnabled        2026-08-01
DC Security Baseline        AllSettingsEnabled        2026-07-15
Legacy Workstation Policy   AllSettingsDisabled       2025-01-10
```

**Potential finding**

```text
Finding ID: AD-007
Category: Group Policy
Status: REVIEW
Evidence: DC Security Baseline exists, but effective policy has not been verified.
Risk: Required security settings may not be applied.
Recommendation: Review GPO links, filtering, inheritance, and resultant policy.
```

**Auditor's interpretation:** Confirm whether the expected policies are applied to the intended systems. A disabled GPO is not automatically a violation if its purpose is documented or another control provides the required protection.

### Example 8: Active Directory Replication

**Example output**

```text
Source DSA       largest delta    fails/total    %% error
DC01             00:05:12         0 / 10         0
DC02             03:45:00         2 / 10         20
```

**Potential finding**

```text
Finding ID: AD-008
Category: Directory Health
Status: REVIEW
Evidence: DC02 reports 2 replication failures out of 10 attempts.
Risk: Replication issues may delay directory changes and affect administrative consistency.
Recommendation: Investigate the reported errors and validate replication health after remediation.
```

**Auditor's interpretation:** Investigate the specific replication errors and verify the outcome after remediation. The example values are fictional and do not establish that a security breach occurred.

### Example 9: Security Event Review

**Example output**

```text
TimeCreated          Id     MachineName
-----------          --     -----------
2026-10-22 09:15:00  4720   DC01
2026-10-22 09:18:00  4728   DC01
2026-10-22 11:30:00  1102   DC01
```

**Potential finding**

```text
Finding ID: AD-009
Category: Security Monitoring
Status: REVIEW
Evidence: Event ID 4728 was recorded on DC01.
Risk: An unauthorized group membership change could increase privileges.
Recommendation: Inspect the full event, identify the affected group and member, and correlate with approved change records.
```

**Auditor's interpretation:** Inspect the full event details and surrounding activity. Event ID 4728 relates to a member being added to a security-enabled global group; it does not, by itself, prove the change was unauthorized. Correlate all relevant events with approved changes and the applicable audit scope.

## Example Final Audit Summary

The following summary is hypothetical. The counts are illustrative and are not calculated automatically from the sample outputs above.

```text
Active Directory Hardening Audit
---------------------------------
Controls reviewed:       9
PASS:                    2
FAIL:                    2
REVIEW:                  5
NOT TESTED:              0

Priority follow-up:
1. Validate privileged group membership.
2. Review password policy against the approved baseline.
3. Investigate SMBv1 configuration on Domain Controllers.
4. Confirm Domain Controller support and patch status.
5. Investigate replication failures and unexpected security events.
```

A real audit summary should be generated from verified findings, not copied from this fictional example.

## Auditor's Decision Rules

Before recording a final finding:

1. **Confirm the evidence:** Verify that the output came from the correct domain, host, and time period.
2. **Identify the requirement:** Reference the approved organizational baseline or applicable control.
3. **Assess the impact:** Explain the potential security or operational consequence.
4. **Validate exceptions:** Check documented business needs and approved deviations.
5. **Record the result:** Use `PASS`, `FAIL`, `REVIEW`, or `NOT TESTED` consistently.
6. **Preserve evidence safely:** Redact sensitive information before sharing reports or publishing examples.
7. **Document limitations:** Record unavailable logs, insufficient permissions, failed commands, and checks that were not performed.

A successful audit is not simply a report with zero failures. It is a documented assessment in which each conclusion is supported by evidence and an explicit security requirement.

## Reporting and Evidence

For each finding, record:

- Finding ID.
- Control category.
- Status and severity, where applicable.
- Affected host, account, group, or policy.
- Evidence and collection timestamp.
- Applicable organizational requirement.
- Risk or operational impact.
- Recommended next step.
- Owner, target date, and remediation status, if tracked by the organization.

Keep raw evidence separate from public project documentation. Audit output may contain usernames, domain information, hostnames, security configuration details, and other sensitive organizational data.

Do not publish real audit reports, credentials, internal host inventories, or identifiable environment details in a public repository.

## Safety and Limitations

- This project is intended for authorized defensive security assessments.
- The checks are designed to be read-only; they do not automatically remediate findings.
- Read-only does not mean risk-free: commands can expose sensitive information or generate audit activity.
- Some commands inspect only the local host or the default domain policy.
- Results may be incomplete because of permission limitations, unavailable logs, missing modules, replication delays, or environmental differences.
- A command returning no results does not always prove that a control is correctly configured.
- The sample output is fictional and should not be treated as real audit evidence.
- No universal baseline is assumed. Requirements must come from the organization's approved standards, applicable regulations, or formally adopted security framework.

**Do not run configuration changes or remediation commands as part of an audit without the appropriate authorization and change approval.**

## Contributing

Contributions are welcome, including:

- Additional read-only audit checks.
- Improved evidence collection.
- Better error handling and reporting.
- Documentation improvements.
- Example findings based on clearly fictional data.
- Compatibility improvements for supported PowerShell environments.

Contributions should explain the check's scope, required permissions, expected output, limitations, and how findings should be validated.

## Disclaimer

This repository is provided for educational and defensive security purposes. It is not a guarantee of security or compliance, and it does not replace a comprehensive assessment by qualified personnel.

Users are responsible for obtaining authorization, protecting audit evidence, validating findings, and following applicable organizational policies and legal requirements.

