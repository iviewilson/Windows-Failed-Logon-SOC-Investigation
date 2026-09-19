# Windows Failed Logon & Account Activity Investigation

## SOC Incident Investigation | SOC-IR-002

### Overview

This project documents a SOC investigation into a cluster of failed Windows authentication events detected on a monitored endpoint using Wazuh SIEM.

The investigation began with multiple Windows Security Event ID 4625 events occurring within a short time window. Rather than treating every failed authentication event as malicious, the activity was investigated by correlating authentication failures with process creation and account-management telemetry.

The investigation included analysis of:

- Windows Event ID 4625 — Failed logon
- Windows Event ID 4688 — Process creation
- Windows Event ID 4738 — User account changed
- Authentication source and logon type
- Account lockout activity
- Account creation and privileged-group modification activity
- Processes occurring around the authentication timeline

### Investigation Objective

Determine whether the observed authentication failures represented a brute-force attempt, successful account compromise, or other suspicious activity, and identify any evidence of subsequent account manipulation or malicious process execution.


## Lab Environment

| Component | Details |
|---|---|
| SIEM | Wazuh |
| Endpoint | Windows 11 |
| Wazuh Agent | IVIE-WINDOWS-ENDPOINT |
| Log Source | Windows Security Event Log |
| Environment | Controlled home SOC lab |
| Investigation Type | Authentication and account activity investigation |

## Incident Timeline

During threat hunting, multiple Windows failed-logon events were identified and correlated with surrounding endpoint activity.

| Time (Sep 18, 2026) | Event | Analyst Observation |
|---|---|---|
| 15:38:28–15:38:29 | Event ID 4738 | Three user-account-change events involving the `iivie` account were observed before the authentication cluster. |
| 15:56:15 | Event ID 4625 | First failed interactive logon in the observed cluster. |
| 15:56:20 | Event ID 4625 | Second failed interactive logon. |
| 15:56:27 | Event ID 4625 | Third failed interactive logon. |
| 15:56:30 | Event ID 4625 | Fourth failed interactive logon. |
| 15:57:07 | Event ID 4688 | `svchost.exe` process creation observed with `services.exe` as its parent process. |
| 15:57:07 | Event ID 4738 | Two additional account-change events involving `iivie` occurred near the authentication activity. |
| 16:04:12 | Event ID 4625 | Separate failed logon associated with Logon Type 4 and Dell SupportAssist process context. |

### Initial Hypothesis

The concentration of failed interactive logons warranted investigation for possible password guessing or unauthorized authentication activity. The investigation therefore focused on determining whether the failures originated remotely, whether authentication subsequently succeeded, and whether the activity was followed by account manipulation, privilege changes, or suspicious process execution.
