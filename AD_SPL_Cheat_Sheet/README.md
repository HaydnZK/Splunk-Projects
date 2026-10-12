# AD Splunk Cheat sheet
## Relevant Event IDs

| Category | Event ID | Description |
|---|---|---|
| Account & Group Management | 4720 | A user account was created. |
| Account & Group Management | 4722/4725 | A user account was enabled (4722) or disabled (4725). |
| Account & Group Management | 4726 | A user account was deleted. |
| Account & Group Management | 4724 | An attempt was made to reset an account's password. |
| Account & Group Management | 4740 | A user account was locked out. |
| Account & Group Management | 4728/4732/4756 | Member added to a security-enabled global (4728), local (4732), or universal (4756) group. |
| Authentication & Logon Activity | 4624 | Successful logon (check for anomalous logon types like Type 10 RDP or Type 3 network logons). |
| Authentication & Logon Activity | 4625 | Failed logon (indicators of brute-force or credential stuffing attacks). |
| Authentication & Logon Activity | 4648 | Logon using explicit credentials (runas). Used during lateral movement. |
| Authentication & Logon Activity | 4672 | Special privileges assigned to a new logon (indicates administrative/system token assignment). |
| Authentication & Logon Activity | 4768 | A Kerberos authentication ticket (TGT) was requested (useful for catching Golden Ticket pre-auth failures / ID 4771). |
| Authentication & Logon Activity | 4769 | A Kerberos service ticket (TGS) was requested (primary event for detecting Kerberoasting and Silver Tickets). |
| Directory Services & Replication (AD Specific) | 4662 | An operation was performed on an object (monitored closely for DCSync attacks via replication rights requests). |
| Directory Services & Replication (AD Specific) | 4794 | An attempt was made to set the Directory Services Restore Mode (DSRM) administrator password. |
| Directory Services & Replication (AD Specific) | 5136 | A directory service object was modified. |
| Directory Services & Replication (AD Specific) | 5141 | A directory service object was deleted (indicates attacker cleanup or malicious object removal). |
| System Integrity & Audit Changes | 1102 | The audit log was cleared. |
| System Integrity & Audit Changes | 4719 | System audit policy was changed. |
| System Integrity & Audit Changes | 4697/7045 | A service was installed in the system (highly indicative of lateral movement via PsExec or persistence). |
| System Integrity & Audit Changes | 4104 | PowerShell script block logging (critical for script execution visibility). |
| Credential Dumping & Object Access | 4663 | An attempt was made to access an object (monitored on lsass.exe to catch credential dumping tools like Mimikatz). |
| Lateral Movement & Share Access | 5140 | A network share object was accessed (tracks connection to standard and administrative shares like C or ADMIN). |
| Lateral Movement & Share Access | 5145 | A network share object was checked to see whether client can be granted access (detailed tracking of specific files running over SMB). |
| Sysmon (System Monitor) Activity | 1 | Process creation (identifies malicious command-line parameters, spawned shells, and execution). |
| Sysmon (System Monitor) Activity | 3 | Network connection detected (maps processes to destination IPs/ports). |
| Sysmon (System Monitor) Activity | 11 | File create (tracks when files are written to disk, vital for web shell or payload deployment detection). |
| Sysmon (System Monitor) Activity | 22 | DNSEvent (DNS query success or failure, useful for identifying C2 beacons and data exfiltration domains). |

---

## Initial Access: Web Shells
### Identify Scanning Activity
```spl
index=iis sc_status=404
| stats count by c_ip
| sort - count
```

### Finding Suspicious Files
```spl
index=iis c_ip={SUSPICIOUS_IP} sc_status=200
| stats count by cs_uri_stem
| sort - count
```

### Filtering for the Suspicious Files
```spl
index=iis cs_uri_stem="*/{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```

### Trace the Sysmon Process Chain
```spl
index=win EventCode=1 ParentImage="*\\w3wp.exe"
| table _time, ParentImage, CommandLine
| sort _time
```

### Find When the Web Shell was Deployed
```spl
index=win EventCode=11 TargetFilename="*{WEBSHELL_FILENAME}"
| table _time, Image, TargetFilename
```

#### **If There's No Event ID 11**

```spl
index=iis cs_method=POST cs_uri_query="*{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_uri_stem, cs_uri_query, sc_status
| sort _time
```

---

## Initial Access: OWA Brute Force
### Find Authentication Failures Against OWA
```spl
index=iis cs_uri_stem="/owa/auth.owa" cs_method=POST
| bin _time span=5m
| stats count by _time, c_ip
| where count > 10
| sort - count
```

### Identify the Targeted Account
```spl
index=win EventCode=4625
| stats count by user, Logon_Type
| sort - count
```

### Correlate Logins with Windows Security Logs
```spl
index=win EventCode IN (4624, 4625) user="{TARGETED_USER}" Logon_Type=8
| table _time, EventCode, user, Process_Name, Logon_Type
| sort _time
```

### Check for Post-Authentication Activity
```spl
index=iis c_ip="{ATTACKER_IP}"
| stats count by cs_uri_stem
| sort - count
```

---

## Initial Access: VPN Credential Attacks
### Identify the Scope of the Attack
```spl 
index=win EventCode=6273
| stats count by User_Account_Name, Client_IP_Address
| sort - count
```

### Find the Compromised Account
```spl
index=win EventCode IN (6273,6272) User_Account_Name={COMPROMISED_USER}
| table _time, EventCode, User_Account_Name, Client_IP_Address
```

### Correlate with Security Logon Events
```spl
index=win EventCode IN (4624, 4625) user={COMPROMISED_USER}
| table _time, host, user, EventCode, Logon_Type
| sort _time
```
---

## Credential Attacks: Kerberoasting
### Searching for RC4 Downgrading to Exclude Normal Traffic
```spl
index=<INDEX> EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```

### How Many Service Accounts, Which Account, and Where
```spl
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| stats dc(Service_Name) as targeted_services count by Account_Name, Client_Address
```

### Detection Evasion VIA AES Cracking | Quantity-Based Hunting
```spl
index=task2 EventCode=4769 Service_Name!="*$" Service_Name!="krbtgt"
| bin _time span=5m
| stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
| where unique_spns > 5
```

---

## Credential Attacks: AS-REP Roasting
### Taking a Look at Normal TGT Traffic
```spl
index=<INDEX> EventCode=4768
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
| sort _time
```

### Isolating RC4 Encryption
```spl
index=<INDEX> EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
```

### Checking for Normal Post-TGS Request (4679) or Logon (4624) Activity 
```spl
index=task3 (EventCode=4624 OR EventCode=4769)
| search Account_Name="<ACCOUNT_NAME>"
| table _time, EventCode, Account_Name, Client_Address
```
- **Note**: Seeing no activity in the results is a red flag. 

---

## Credential Attacks: LSASS Credential Dumping
### Viewing All LSASS Traffic
```spl
index=task4 EventCode=10 TargetImage="*\\lsass.exe"
| stats count by SourceImage, GrantedAccess
```

### Examining Suspicious Results' CallTrace
```spl
index=<INDEX> EventCode=10 TargetImage="*\\lsass.exe" SourceImage=<SUSPICIOUS_PROCESS>
| table _time, SourceImage, SourceUser, GrantedAccess, CallTrace
```

---

## Credential Attacks: DCSync 
### Searching for DS-Replication-Get-Changes-All (1131f6ad) and Filtering Machine Accounts
```spl
index=<INDEX> EventCode=4662 "1131f6ad" user!="*$"
| table _time, user, Access_Mask, Properties
| sort _time
```

### Correlating Logon_ID Between Events 4662 and 4624
```spl
index=<INDEX> EventCode=4662 Access_Mask=0x100 user=<COMPROMISED_USER> "1131f6ad"
| table _time, host, user, Logon_ID
```

### Finding the Originating Source IP
```spl
index=task5 EventCode=4624 Logon_ID=<LOGON_ID>
| table _time, host, user, Source_Network_Address, Logon_Type
```

---

## Credential Attacks: NTDS.dit Extraction 
### Finding `ntdsutil.exe` as an Extraction Method
```spl
index=<INDEX> EventCode=1 Image="*\ntdsutil.exe"
| table _time, host, User, ParentImage, Image, CommandLine
```

### Confirmation of Expected File Extraction
```spl 
index=task6 EventCode=11 TargetFilename="*ntds.dit" Image="*\\ntdsutil.exe"
| table _time, Image, TargetFilename
```

### Finding Shadow Copy Creation
```spl
index=task6 EventCode=1 Image="*\vssadmin.exe" CommandLine="*create shadow*"
| table _time, host, User, ParentImage, Image, CommandLine
```

### Correlating Shadow Copy Creation with Sensitive Files
```spl
index=task6 EventCode=1 CommandLine="*HarddiskVolumeShadowCopy*" (CommandLine="*ntds*" OR CommandLine="*SYSTEM*")
| table _time, host, User, ParentImage, Image, CommandLine
```

---

## Detecting AD Lateral Movement
## Lateral Movement: Discovery & Recon
---
## Lateral Movement: Detecting SMB Lateral Movement
---
## Lateral Movement: Detecting PsExec Lateral Movement
---
## Lateral Movement: Detecting RDP Lateral Movement
---

