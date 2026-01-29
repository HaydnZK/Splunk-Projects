#Part One: Setting Up and Configuring Splunk 
## Overview
In this portion of the lab, I set up Splunk Enterprise as a centralized logging and monitoring platform and configured it to ingest multiple 
Linux log sources in real time.

The goal was to build a functional SIEM environment capable of detecting authentication abuse, privilege escalation, sensitive file access, 
and system changes before performing any attack simulation.

Rather than relying on prebuilt datasets, all logs were generated organically by the operating system and user activity to reflect how Splunk 
is used in real environments.

Three primary data sources were configured:
- Linux authentication logs for login attempts and privilege escalation
- Linux audit logs for file access, permission changes, and account modifications
- Linux system logs for background services and operating system events

By configuring continuous file monitoring and proper source types, Splunk was able to index security‑relevant activity in near real time and 
provide the visibility required to later reconstruct the full attack timeline and trigger alerts on suspicious behavior.

This setup established the foundation for all detection, alerting, and investigation performed in the remainder of the lab.

## Splunk Installation
### Package selection
I downloaded:
- Splunk Enterprise for Linux (.deb)

This option integrates cleanly with Ubuntu’s package manager.

### Installation command:
```bash
sudo dpkg -i splunk-<version>-linux-amd64.deb
```

Initial startup:
```bash
sudo /opt/splunk/bin/splunk start --accept-license
```

Splunk was then configured to start automatically on boot:
```bash
sudo /opt/splunk/bin/splunk enable boot-start
```

The web interface was accessed at:
`http://Ubuntu-Splunk:8000`

An admin account was created during first launch.

## Log Forwarding and Data Ingestion Configuration
Instead of using external forwarders, I configured Splunk to monitor local log files directly on the system. This mirrors how a Splunk Universal 
Forwarder would collect logs from Linux hosts in production.

Each log source was added using the Splunk Web UI.

### Path:
`Settings > Add Data > Files & Directories > Monitor files`

## Data Source 1: Linux Authentication Logs
### Log file:
`/var/log/auth.log`

### Configuration:
- Input type: File monitor
- Monitoring: Continuous
- Source type: linux_auth_log
- App context: search
- Host: haydn-virtualbox
- Index: default

### Purpose:
- Capture SSH login attempts
- Capture sudo usage
- Capture su authentication
- Track session creation and failures

### Example activity captured:
- Failed SSH passwords
- Successful logins
- sudo authentication events
- su privilege escalation attempts

## Data Source 2: Linux Audit Logs
### auditd installation:
```bash
sudo apt install auditd audispd-plugins -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

### Log file:
`/var/log/audit/audit.log`

### Configuration:
- Input type: File monitor
- Monitoring: Continuous
- Source type: linux_audit
- App context: search
- Host: haydn-virtualbox
- Index: default

### Purpose:
- Track file access
- Track permission changes
- Track user creation
- Track sensitive directory access

### This log source is critical for detecting:
- Access to /etc/passwd
- Reads of sensitive files
- chmod operations
- Data staging activity

## Data Source 3: Linux System Logs
### Log file:
`/var/log/syslog`

### Configuration:
- Input type: File monitor
- Monitoring: Continuous
- Source type: syslog
- App context: search
- Host: haydn-virtualbox
- Index: default

### Purpose:
- Capture system service activity
- Capture application messages
- Track background processes and system changes

## Verification of Log Forwarding
To verify that logs were being collected correctly, I generated test activity:
```bash
sudo whoami
sudo su
```

and performed multiple failed login attempts.

### Verification search:
```bash
index=default
```

and:
```bash
index=default sourcetype=linux_auth_log
```

This confirmed that:
- New events were indexed in real time
- Authentication failures appeared correctly
- sudo activity was logged
- auditd events were ingested

## Final Result
At the end of this, Splunk was successfully collecting:
- Authentication logs
- Audit logs
- System logs

All logs were continuously monitored and indexed, allowing for:
- Real-time alerting
- Timeline reconstruction
- User activity tracking
- Privilege escalation detection
- File access monitoring

This SIEM configuration served as the foundation for the internal credential compromise lab and all subsequent detection and investigation work.



# Part Two: Internal Credential Compromise Portion
## Overview
In this lab, I simulated an internal attacker gaining access to my Linux system, escalating privileges, discovering sensitive financial data, 
exfiltrating it, and creating persistence. The goal was to generate realistic log activity and then later detect and investigate it using Splunk.

This scenario represents a common real-world situation such as stolen credentials, password reuse, or a compromised internal workstation.

### Splunk data sources used:
- Linux_Auth
- Linux_Audit
- Linux_Syslog

## Phase 1: Initial Access (Brute Force Simulation)
I started by simulating a brute force style login into a low-privileged account named:
`eviluser`

I simulated  brute-force attempt by entering incorrect passwords several times before logging in successfully to generate authentication failures 
followed by a success in the logs.

### Purpose:
- Generate failed login events
- Show how brute force or credential guessing appears in authentication logs
- Establish an initial foothold as a non-privileged user

#### Logs generated:
- Linux_Auth

## Phase 2: Reconnaissance as eviluser
Once logged in, the attacker begins gathering information about the system.

### Commands used:
```bash
whoami
id
hostname
cat /etc/passwd
getent group sudo
```

### What this accomplishes:
- Identifies the current user
- Lists all local user accounts
- Determines which users belong to the sudo group

From this, the attacker learns that the account:
`haydn`

has sudo privileges.
This is a common real-world step attackers take after gaining access.

#### Logs generated:
- Linux_Audit (file access to /etc/passwd)
- Linux_Syslog

## Phase 3: Privilege Escalation via Password Reuse
The attacker then attempts to become the privileged user.

### Command:
```bash
su haydn
```

After several attempts, the password is successfully guessed, simulating password reuse between accounts.
This results in the attacker gaining access to an account with sudo privileges.

### Why this is realistic:
- Password reuse is extremely common
- Many real breaches happen this way
- No exploit is required, only weak credentials

#### Logs generated:
- Linux_Auth (su authentication and session open)

## Phase 4: System and Data Discovery as haydn
With elevated privileges, the attacker searches the system for valuable data.

### Commands:
```bash
sudo ls /
sudo ls /opt
sudo cd /opt/finance
sudo ls -la
```

The attacker discovers a directory:
`/opt/finance`

and inside it:
- secret.txt

This approach is realistic because attackers typically enumerate directories rather than guessing filenames.

#### Logs generated:
- Linux_Audit
- Linux_Syslog

## Phase 5: Sensitive File Access
The attacker reads the file:
```bash
sudo cat /opt/finance/secret.txt
```

The file contains simulated sensitive financial information.
At this point, the attacker has successfully accessed protected data.

#### Logs generated:
- Linux_Audit (file access)

## Phase 6: Permission Tampering
To ensure easier future access, the attacker weakens file permissions:
```bash
sudo chmod 777 /opt/finance/secret.txt
```

This allows any user to read, write, or modify the file.

### Why attackers do this:
- Makes future access easier
- Allows other compromised accounts to read the data
- Often overlooked by defenders

#### Logs generated:
- Linux_Audit
- Linux_Syslog

## Phase 7: Data Exfiltration (Simulated)
Since this is a single system lab, exfiltration was simulated by staging the data into the attacker’s account.

### First, a home directory was created for eviluser:
```bash
sudo mkdir /home/eviluser
sudo chown eviluser:eviluser /home/eviluser
sudo chmod 700 /home/eviluser
```

Then the file was copied:
```bash
sudo mv /opt/finance/5ecret.txt /home/eviluser/secret.txt
sudo chown eviluser:eviluser /home/eviluser/secret.txt
```

### This represents:
- Data staging
- Preparing the file for removal via USB, SCP, or other methods

### Why this is realistic:
- Attackers often collect data in one place before exfiltrating
- Home directories and /tmp are common staging locations

#### Logs generated:
- Linux_Audit
- Linux_Syslog

## Phase 8: Persistence (Backdoor Account)
To maintain long-term access, the attacker creates a new admin account:
```bash
sudo useradd -m sys_backup
sudo passwd sys_backup
sudo usermod -aG sudo sys_backup
```

The name was chosen to look legitimate and blend in with system accounts.

### This provides:
- Persistent access
- Full administrative privileges
- A fallback even if original accounts are secured

#### Logs generated:
- Linux_Audit
- Linux_Syslog
- Linux_Auth

## Final Result
This lab successfully simulated:
- Brute force login attempts
- User enumeration
- Privilege escalation via password reuse
- Sensitive data discovery
- Unauthorized file access
- Permission tampering
- Data staging for exfiltration
- Persistence through a backdoor admin account

All activity generated realistic log data across authentication logs, audit logs, and system logs, which can now be analyzed and correlated in 
Splunk to reconstruct the full attack timeline.



# Part Two: Attack Investigation and Log Analysis Using Splunk
## Overview
After completing the attack simulation, I transitioned into the blue team role and investigated the activity using Splunk.

The goal of this phase was to:
- Identify how the attacker gained access
- Confirm which account was compromised
- Track privilege escalation
- Reconstruct system enumeration
- Detect sensitive file access and data exfiltration
- Identify persistence mechanisms
- Attribute activity across user sessions

All analysis was performed using the previously ingested log sources:
- Linux_Auth
- Linux_Audit
- Linux_Syslog

## Phase 1: Detecting Initial Access (Brute Force Login)
The investigation began by searching for authentication failures in the authentication logs:
```bash
sourcetype=Linux_Auth "authentication failure"
```

This returned multiple failed login attempts.
Using the fields panel, the user field was reviewed, which showed two primary accounts:
- haydn
- eviluser

To quantify the activity, the following was used:
```bash
sourcetype=Linux_Auth "authentication failure"
| stats count by user
```

This showed that:
- eviluser had 17 failed login attempts
- haydn had significantly fewer

This indicated targeted credential guessing against the eviluser account.

To visualize the behavior over time:
```bash
sourcetype=Linux_Auth user=eviluser
| timechart count
```

This displayed a spike in authentication failures clustered closely together.

To validate the behavior, raw logs were reviewed using the event source view, which showed repeated failed password attempts.

Finally, successful access was confirmed using:
```bash
sourcetype=Linux_Auth "session opened" eviluser
```

This verified that the attacker successfully logged into the system as eviluser after the failed attempts.

## Phase 2: Reconnaissance and Internal Enumeration
After confirming the compromise of eviluser, audit logs were reviewed to understand what actions the attacker took next.

A broad search was performed:
```bash
sourcetype=Linux_Audit "eviluser"
```

This returned 774 events involving the compromised account.

Reviewing the exe field revealed the use of:
- `/usr/bin/sudo`
- `/usr/bin/su`
- `/usr/bin/ls`
- `/usr/bin/passwd`
- `/usr/bin/useradd`
- `/usr/bin/usermod`

To investigate further the following search was used:
```bash
sourcetype=Linux_Audit "/usr/bin/passwd"
```

This revealed two important findings:
- eviluser accessing the passwd binary
- An unfamiliar account named sys_backup appearing in nearby events

Reviewing the source logs confirmed that the attacker accessed password-related system components.

Additional raw logs also showed the attacker inspecting:
```bash
/usr/bin/sudo
```

indicating reconnaissance to determine which users had sudo privileges.

This confirmed that the attacker was actively enumerating users and privilege boundaries.

## Phase 3: Privilege Escalation via su
Next, authentication logs were reviewed for privilege escalation activity:
```bash
sourcetype=Linux_Auth "su"
```

This returned 36 events.

Reviewing the timeline showed:
- Multiple failed attempts to authenticate into haydn
- A successful session open from eviluser to haydn

The successful event was confirmed using the source log view, showing:
- Authentication success
- Session opened for user haydn

This confirmed that the attacker escalated privileges using:
```bash
su haydn
```

and gained access to an account with sudo rights.

## Phase 4: Filesystem Discovery and Targeted Directory Enumeration
Following privilege escalation, filesystem activity was analyzed.

A general search was performed:
```bash
sourcetype=* "ls /"
```

This immediately revealed that the haydn account was accessing:
```bash
/opt/finance
```

which was unexpected for normal activity.

To investigate further:
```bash
sourcetype=* "/opt/finance"
```

This revealed several important events:
- eviluser previously attempted to access /opt/finance and was denied
- Access succeeded later using the haydn account
- A file named 5ecret.txt appeared in the directory
- secret.txt was copied and renamed
- The file was moved into the eviluser home directory

Reviewing the source logs confirmed the following command activity:
```bash
ls /
ls /lib
ls /opt
cd /opt/finance
ls -la
cp secret.txt 5ecret.txt
mv 5ecret.txt /home/eviluser/
```

This showed a clear progression:
- Broad directory enumeration
- Discovery of /opt
- Identification of /opt/finance
- Sensitive file interaction
- Data staging into attacker-controlled storage

## Phase 5: Data Exfiltration Staging
Audit logs confirmed that the attacker:
- Renamed secret.txt to 5ecret.txt
- Copied the file
- Moved it to `/home/eviluser`

This represented data staging in preparation for exfiltration via removable media or network transfer.

This activity occurred only after privilege escalation, further confirming intent and planning.

## Phase 6: Persistence via Backdoor Account Creation
To investigate persistence, the previously observed account was examined:
```bash
sourcetype=Linux_Audit "sys_backup"
```

This revealed the following sequence:

At the bottom of the events:
```bash
useradd sys_backup
```

Above it:
```bash
passwd sys_backup
usermod -aG sudo sys_backup
```

This confirmed:
- A new account was created
- A password was assigned
- The account was added to the sudo group

Granting full administrative privileges.

## Phase 7: Attribution Using uid and auid
While reviewing the usermod event source logs, two key fields were identified:
- uid = haydn
- auid = eviluser

This indicates:
- The command was executed while operating as haydn
- The session originated from eviluser

This confirms the full chain:
- Initial compromise of eviluser
- Privilege escalation to haydn
- Creation of persistent backdoor sys_backup

Even though the final actions were performed as haydn, audit logs preserved attribution to the original attacker account.

## Final Result
Using Splunk, the following attack chain was fully reconstructed:
- Brute force login against eviluser
- Successful authentication
- Internal reconnaissance and privilege discovery
- Privilege escalation via su haydn
- Filesystem enumeration
- Discovery of sensitive financial data
- File access, renaming, and staging for exfiltration
- Creation of a privileged backdoor account
- Attribution across privilege escalation boundaries using auid tracking

This investigation demonstrates how authentication logs and audit logs can be correlated to reconstruct attacker behavior, identify 
persistence mechanisms, and attribute activity to the original compromised account.
