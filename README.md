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
