import { cmdQuote, psQuote } from './shell.ts';

/**
 * A curated reference of well-known Windows event IDs. It covers the events
 * admins meet most, not every event Windows can log. Titles and meanings are
 * summaries in our own words, not the message text of the event.
 */
export interface WindowsEvent {
  id: number;
  /** Provider name as shown in Event Viewer's Source column. */
  source: string;
  /** Channel: Security, System, Application, or a full channel name. */
  log: string;
  category: string;
  title: string;
  meaning: string;
  check: string;
}

const SEC = 'Microsoft-Windows-Security-Auditing';
const EVENTLOG = 'Microsoft-Windows-Eventlog';
const SCM = 'Service Control Manager';
const KPOWER = 'Microsoft-Windows-Kernel-Power';
const KGENERAL = 'Microsoft-Windows-Kernel-General';
const GP = 'Microsoft-Windows-GroupPolicy';
const WU = 'Microsoft-Windows-WindowsUpdateClient';
const WHEA = 'Microsoft-Windows-WHEA-Logger';
const DCOM = 'Microsoft-Windows-DistributedCOM';
const PS = 'Microsoft-Windows-PowerShell';
const PS_LOG = 'Microsoft-Windows-PowerShell/Operational';
const PS_CLASSIC_LOG = 'Windows PowerShell';
const LSM = 'Microsoft-Windows-TerminalServices-LocalSessionManager';
const LSM_LOG = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';
const RCM = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager';
const RCM_LOG = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational';
const TASKS = 'Microsoft-Windows-TaskScheduler';
const TASKS_LOG = 'Microsoft-Windows-TaskScheduler/Operational';
const DEFENDER = 'Microsoft-Windows-Windows Defender';
const DEFENDER_LOG = 'Microsoft-Windows-Windows Defender/Operational';
const FIREWALL = 'Microsoft-Windows-Windows Firewall With Advanced Security';
const FIREWALL_LOG = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';

const LOGON = 'Logon and sessions';
const KERBEROS = 'Kerberos and NTLM';
const ACCOUNTS = 'Accounts';
const GROUPS = 'Groups';
const AUDIT = 'Audit and policy';
const PROCESS = 'Processes and tasks';
const OBJECTS = 'Files, shares and objects';
const DIRECTORY = 'Active Directory';
const FW = 'Firewall';
const BOOT = 'Startup and shutdown';
const SERVICES = 'Services';
const HARDWARE = 'Disk and hardware';
const NETWORK = 'Network and domain';
const UPDATE = 'Windows Update';
const APPS = 'Applications';
const POWERSHELL = 'PowerShell';
const RDP = 'Remote Desktop';
const SCHEDULER = 'Task Scheduler';
const ANTIVIRUS = 'Windows Defender';

function ev(id: number, source: string, log: string, category: string, title: string, meaning: string, check: string): WindowsEvent {
  return { id, source, log, category, title, meaning, check };
}

const GROUP_CHECK = 'Look at who made the change and which group it is. Changes to Administrators, Domain Admins, Enterprise Admins and Remote Desktop Users matter most.';
const TASK_AUDIT = 'Logged only when the audit subcategory Other Object Access Events is on.';
const DISK_CHECK = 'Check the disk health (SMART, vendor diagnostics), cables and the controller driver and firmware. Back up the disk before anything else.';
const TASK_HISTORY = 'This log is empty unless task history is enabled in Task Scheduler.';

export const WINDOWS_EVENTS: WindowsEvent[] = [
  // Security log: audit and policy
  ev(1100, EVENTLOG, 'Security', AUDIT, 'Event logging service shut down', 'The Windows Event Log service stopped. This is normal during a shutdown or restart.', 'If the computer did not restart at that time, find out who stopped the service, because nothing is logged while it is down.'),
  ev(1102, EVENTLOG, 'Security', AUDIT, 'Security log cleared', 'The Security audit log was cleared. The event names the account that cleared it.', 'Confirm it was planned. An unexpected clear is a common way to hide activity, so review what that account did before and check any forwarded copy of the log.'),
  ev(1104, EVENTLOG, 'Security', AUDIT, 'Security log is full', 'The Security log reached its maximum size and cannot take new events with the current retention setting.', 'Raise the maximum log size or let old events be overwritten. Events are lost until this is fixed.'),
  ev(4608, SEC, 'Security', BOOT, 'Windows is starting up', 'Logged when the security subsystem starts during boot.', 'Use it as a boot marker in the Security log.'),
  ev(4616, SEC, 'Security', AUDIT, 'System time changed', 'The system clock was changed. The event holds the old and new time and the process that made the change.', 'Small corrections by the Windows Time service are normal. A change by a user or another process deserves a look: it breaks Kerberos and distorts log timestamps.'),
  ev(4719, SEC, 'Security', AUDIT, 'Audit policy changed', 'The system audit policy was changed. The event lists the subcategory and what was added or removed.', 'Make sure the change came from Group Policy or a planned action. Turning auditing off is a typical step before unwanted activity.'),
  ev(4704, SEC, 'Security', AUDIT, 'User right assigned', 'A user right (privilege), such as Log on as a service or Debug programs, was granted to an account.', 'Check which right was granted, to whom and by whom. Rights such as Debug programs or Act as part of the operating system are powerful.'),
  ev(4705, SEC, 'Security', AUDIT, 'User right removed', 'A user right (privilege) was removed from an account.', 'Check that the removal was intended. A service can stop working after losing Log on as a service.'),
  ev(4739, SEC, 'Security', AUDIT, 'Domain policy changed', 'The domain policy was changed, for example the password or account lockout policy.', 'Review which setting changed and who changed it.'),

  // Security log: logon and sessions
  ev(4624, SEC, 'Security', LOGON, 'Successful logon', 'An account logged on to this computer. The event holds the logon type, the account, the source workstation and address, and the authentication package.', 'Read the logon type to see how the account came in (console, network, Remote Desktop, service). Check the source address and whether this account should log on here. Event 4672 next to it means the account has administrator-level privileges.'),
  ev(4625, SEC, 'Security', LOGON, 'Failed logon', 'A logon attempt failed. The event holds the account name, logon type, source address and the Status and Sub Status codes that give the reason.', 'Read Sub Status for the reason (wrong password, unknown user, locked, disabled). Many failures from one address point to password guessing. Repeated failures for one account from an internal host usually mean a stale saved password.'),
  ev(4634, SEC, 'Security', LOGON, 'Logoff', 'A logon session was closed.', 'Mostly routine. Match the Logon ID with event 4624 to see how long a session lasted. Network logons produce many short sessions.'),
  ev(4647, SEC, 'Security', LOGON, 'User initiated logoff', 'A user started a logoff from an interactive or Remote Desktop session.', 'It marks the end of an interactive session more reliably than 4634, which can come much later.'),
  ev(4648, SEC, 'Security', LOGON, 'Logon with explicit credentials', 'A process logged on with credentials given explicitly while running as another account, as runas, scheduled tasks or mapping a drive with other credentials do.', 'Check which process used the credentials and against which server. Unexpected use by a normal user account towards many servers can indicate lateral movement.'),
  ev(4672, SEC, 'Security', LOGON, 'Special privileges assigned to a new logon', 'The account that just logged on holds sensitive privileges, such as debug, backup or take ownership. In practice it marks an administrator-level logon.', 'Expected for administrators, SYSTEM and many service accounts. Look for accounts that should not have these rights.'),
  ev(4778, SEC, 'Security', LOGON, 'Session reconnected', 'A user reconnected to an existing session, through Remote Desktop or fast user switching. The event holds the client name and address.', 'Check the client address. Together with 4779 it shows when a Remote Desktop session was really in use.'),
  ev(4779, SEC, 'Security', LOGON, 'Session disconnected', 'A user disconnected from a session without logging off, through Remote Desktop or fast user switching.', 'Disconnected sessions keep running programs. Pair it with 4778 to see the connected periods.'),
  ev(4800, SEC, 'Security', LOGON, 'Workstation locked', 'The workstation was locked.', 'Logged only when the audit subcategory Other Logon/Logoff Events is on. Useful for presence timelines.'),
  ev(4801, SEC, 'Security', LOGON, 'Workstation unlocked', 'The workstation was unlocked.', 'Logged only when the audit subcategory Other Logon/Logoff Events is on. An unlock also produces a 4624 with logon type 7.'),

  // Security log: Kerberos and NTLM (domain controllers)
  ev(4768, SEC, 'Security', KERBEROS, 'Kerberos ticket-granting ticket requested', 'Logged on a domain controller when an account asks for a Kerberos ticket-granting ticket (TGT), which happens at logon. The result code is 0x0 on success.', 'For failures read the result code and the client address. Many unknown-user results (0x6) from one address suggest user name guessing.'),
  ev(4769, SEC, 'Security', KERBEROS, 'Kerberos service ticket requested', 'Logged on a domain controller when an account asks for a ticket to a service, such as a file share or a SQL Server.', 'Check the failure code and the service name. One account requesting RC4 tickets (encryption type 0x17) for many services can indicate Kerberoasting.'),
  ev(4770, SEC, 'Security', KERBEROS, 'Kerberos service ticket renewed', 'Logged on a domain controller when a Kerberos service ticket was renewed.', 'Routine. Rarely needs attention on its own.'),
  ev(4771, SEC, 'Security', KERBEROS, 'Kerberos pre-authentication failed', 'Logged on a domain controller when a ticket request failed pre-authentication. The most common reason is a wrong password (0x18).', 'Read the failure code and the client address. This is the Kerberos counterpart of a failed logon and feeds account lockouts.'),
  ev(4776, SEC, 'Security', KERBEROS, 'NTLM credential validation', 'The computer tried to validate credentials with NTLM: a domain controller for domain accounts, the local computer for local accounts. The error code is 0x0 on success.', 'The error code uses the same values as the 4625 Sub Status (for example 0xC000006A wrong password). Source Workstation names where the attempt came from.'),

  // Security log: accounts
  ev(4720, SEC, 'Security', ACCOUNTS, 'User account created', 'A user account was created.', 'Check who created it and whether it was expected. Look for group additions that follow.'),
  ev(4722, SEC, 'Security', ACCOUNTS, 'User account enabled', 'A user account was enabled.', 'Check who enabled it. Re-enabling an old or built-in account without a request is suspicious.'),
  ev(4723, SEC, 'Security', ACCOUNTS, 'Password change attempt', 'A user tried to change their own password, which needs the old password.', 'The event is logged for both success and failure. Read the result in the keywords.'),
  ev(4724, SEC, 'Security', ACCOUNTS, 'Password reset attempt', 'An account tried to reset the password of another account, which does not need the old password.', 'Check who reset whose password. A reset of a privileged account by an unexpected administrator needs an explanation.'),
  ev(4725, SEC, 'Security', ACCOUNTS, 'User account disabled', 'A user account was disabled.', 'Check who disabled it and whether it matches a leaver process or an incident response action.'),
  ev(4726, SEC, 'Security', ACCOUNTS, 'User account deleted', 'A user account was deleted.', 'Check who deleted it. An account created and deleted within a short time is worth a closer look.'),
  ev(4738, SEC, 'Security', ACCOUNTS, 'User account changed', 'Properties of a user account were changed. The event lists the changed attributes.', 'Look at the changed fields, above all the account control flags such as password never expires or password not required.'),
  ev(4740, SEC, 'Security', ACCOUNTS, 'User account locked out', 'An account was locked after too many wrong passwords. For domain accounts it is logged on domain controllers, and the PDC emulator sees every lockout.', 'Read Caller Computer Name, then look on that computer for stale credentials: saved passwords, mapped drives, services, scheduled tasks, phones and mail clients.'),
  ev(4767, SEC, 'Security', ACCOUNTS, 'User account unlocked', 'A locked-out user account was unlocked.', 'Check who unlocked it. If the account locks again soon, find the source with event 4740.'),
  ev(4781, SEC, 'Security', ACCOUNTS, 'Account name changed', 'The logon name of an account was changed. The event holds the old and the new name.', 'Check who renamed it. Renaming can be used to disguise an account.'),
  ev(4741, SEC, 'Security', ACCOUNTS, 'Computer account created', 'A computer account was created, usually because a machine joined the domain.', 'Check who joined the machine and whether it is a known device.'),
  ev(4742, SEC, 'Security', ACCOUNTS, 'Computer account changed', 'A computer account was changed. Computers change their own account password regularly, which also produces this event.', 'Mostly routine. Look at the changed attributes when the change was made by a user.'),
  ev(4743, SEC, 'Security', ACCOUNTS, 'Computer account deleted', 'A computer account was deleted.', 'Check who deleted it. The machine can no longer authenticate to the domain.'),

  // Security log: groups
  ev(4727, SEC, 'Security', GROUPS, 'Global security group created', 'A security-enabled global group was created.', GROUP_CHECK),
  ev(4728, SEC, 'Security', GROUPS, 'Member added to a global security group', 'An account was added to a security-enabled global group, such as Domain Admins.', GROUP_CHECK),
  ev(4729, SEC, 'Security', GROUPS, 'Member removed from a global security group', 'An account was removed from a security-enabled global group.', GROUP_CHECK),
  ev(4730, SEC, 'Security', GROUPS, 'Global security group deleted', 'A security-enabled global group was deleted.', GROUP_CHECK),
  ev(4731, SEC, 'Security', GROUPS, 'Local security group created', 'A security-enabled local group was created: a local group on a computer or a domain local group.', GROUP_CHECK),
  ev(4732, SEC, 'Security', GROUPS, 'Member added to a local security group', 'An account was added to a security-enabled local group, such as Administrators or Remote Desktop Users.', GROUP_CHECK),
  ev(4733, SEC, 'Security', GROUPS, 'Member removed from a local security group', 'An account was removed from a security-enabled local group.', GROUP_CHECK),
  ev(4734, SEC, 'Security', GROUPS, 'Local security group deleted', 'A security-enabled local group was deleted.', GROUP_CHECK),
  ev(4735, SEC, 'Security', GROUPS, 'Local security group changed', 'Properties of a security-enabled local group were changed.', GROUP_CHECK),
  ev(4737, SEC, 'Security', GROUPS, 'Global security group changed', 'Properties of a security-enabled global group were changed.', GROUP_CHECK),
  ev(4756, SEC, 'Security', GROUPS, 'Member added to a universal security group', 'An account was added to a security-enabled universal group, such as Enterprise Admins.', GROUP_CHECK),
  ev(4757, SEC, 'Security', GROUPS, 'Member removed from a universal security group', 'An account was removed from a security-enabled universal group.', GROUP_CHECK),

  // Security log: processes, services, scheduled tasks
  ev(4688, SEC, 'Security', PROCESS, 'Process created', 'A new process started. The event holds the program, the account and the parent process. Logged only when Audit Process Creation is on.', 'Review the parent process and the command line. The command line is recorded only when the policy Include command line in process creation events is enabled.'),
  ev(4689, SEC, 'Security', PROCESS, 'Process exited', 'A process ended. The event holds its exit status.', 'Pair it with 4688 through the process ID to see how long a program ran.'),
  ev(4697, SEC, 'Security', PROCESS, 'Service installed', 'A service was installed. The event holds the service name, file path, start type and account. Logged only when Audit Security System Extension is on.', 'Verify the file path and who installed it. The System log records the same action as event 7045.'),
  ev(4698, SEC, 'Security', PROCESS, 'Scheduled task created', 'A scheduled task was created. The event contains the task name and its full XML definition.', `Review the command the task runs and the account it runs as. ${TASK_AUDIT}`),
  ev(4699, SEC, 'Security', PROCESS, 'Scheduled task deleted', 'A scheduled task was deleted.', `A task created and deleted shortly after can be a way to run a command once. ${TASK_AUDIT}`),
  ev(4700, SEC, 'Security', PROCESS, 'Scheduled task enabled', 'A scheduled task was enabled.', `Check who enabled it and what it runs. ${TASK_AUDIT}`),
  ev(4701, SEC, 'Security', PROCESS, 'Scheduled task disabled', 'A scheduled task was disabled.', `Check who disabled it, above all for backup, update and security tasks. ${TASK_AUDIT}`),
  ev(4702, SEC, 'Security', PROCESS, 'Scheduled task updated', 'A scheduled task was changed. The event contains the new XML definition.', `Compare the new action and account with what the task should do. ${TASK_AUDIT}`),

  // Security log: object access and shares
  ev(4656, SEC, 'Security', OBJECTS, 'Handle to an object requested', 'A process asked for access to a file, registry key or other object. Logged for success or failure when object access auditing is on and the object has an audit entry (SACL).', 'It shows the access that was requested, not what was done. Failures show who was denied. See 4663 for the access actually used.'),
  ev(4663, SEC, 'Security', OBJECTS, 'Object accessed', 'An access right was actually used on a file, registry key or other audited object, for example read, write or delete.', 'Read the Accesses field, the process name and the account. This is the event to use for who changed or deleted a file.'),
  ev(4660, SEC, 'Security', OBJECTS, 'Object deleted', 'An audited object was deleted. The event does not hold the object name.', 'Find the name in the 4663 event with the same handle ID just before it.'),
  ev(4670, SEC, 'Security', OBJECTS, 'Object permissions changed', 'The permissions of an object were changed. The event holds the old and new security descriptor.', 'Check who changed the permissions and whether access was widened.'),
  ev(4657, SEC, 'Security', OBJECTS, 'Registry value modified', 'A registry value was created, changed or deleted in a key that has auditing set.', 'The event holds the old and new value. Watch autostart keys and service settings.'),
  ev(5140, SEC, 'Security', OBJECTS, 'Network share accessed', 'A network share was accessed. Logged once per session the first time the share is used, with the account and the source address. Needs Audit File Share.', 'Use it to see who connected to which share from where. Access to administrative shares (C$, ADMIN$) from workstations deserves a look.'),
  ev(5142, SEC, 'Security', OBJECTS, 'Network share added', 'A network share was created.', 'Check who created the share and which folder it exposes.'),
  ev(5143, SEC, 'Security', OBJECTS, 'Network share modified', 'The settings of a network share were changed.', 'Check what changed, above all the share permissions.'),
  ev(5144, SEC, 'Security', OBJECTS, 'Network share deleted', 'A network share was removed.', 'Check who removed it and whether users or jobs depend on it.'),
  ev(5145, SEC, 'Security', OBJECTS, 'Network share access check', 'A file or folder was requested through a share, with the relative path and the access asked for. Needs Audit Detailed File Share.', 'Very high volume. Filter by share, path or account. Failures show access denied over the network.'),
  ev(6416, SEC, 'Security', OBJECTS, 'New external device recognized', 'The system recognized a new external device, such as a USB drive. Needs Audit PNP Activity.', 'Check the device description and class when removable storage is not allowed.'),

  // Security log: Active Directory changes (domain controllers)
  ev(4662, SEC, 'Security', DIRECTORY, 'Operation on a directory object', 'An operation was performed on an Active Directory object that has auditing set. Needs Audit Directory Service Access.', 'Read the object, the operation type and the properties. High volume, so filter by object or account.'),
  ev(5136, SEC, 'Security', DIRECTORY, 'Directory object modified', 'An attribute of an Active Directory object was changed. The event holds the attribute and the value added or removed. Needs Audit Directory Service Changes.', 'Use it to see exactly what changed on a user, group, GPO or OU and who changed it.'),
  ev(5137, SEC, 'Security', DIRECTORY, 'Directory object created', 'An Active Directory object was created. Needs Audit Directory Service Changes.', 'Check the object class and who created it.'),
  ev(5141, SEC, 'Security', DIRECTORY, 'Directory object deleted', 'An Active Directory object was deleted. Needs Audit Directory Service Changes.', 'Check who deleted it. Deleted objects can be restored from the AD Recycle Bin when it is enabled.'),

  // Security log: firewall and filtering platform
  ev(4946, SEC, 'Security', FW, 'Firewall rule added', 'A rule was added to the Windows Firewall exception list.', 'Check the rule name, the program or port it opens and who added it. Installers add rules too.'),
  ev(4947, SEC, 'Security', FW, 'Firewall rule modified', 'A Windows Firewall rule was changed.', 'Check what the rule allows now.'),
  ev(4948, SEC, 'Security', FW, 'Firewall rule deleted', 'A Windows Firewall rule was deleted.', 'Check whether a block rule or a needed allow rule was removed.'),
  ev(4950, SEC, 'Security', FW, 'Firewall setting changed', 'A Windows Firewall setting was changed, for example a profile was turned on or off.', 'Check which profile and setting changed. A disabled profile leaves the computer open.'),
  ev(5024, SEC, 'Security', FW, 'Firewall service started', 'The Windows Firewall service started.', 'Routine at boot.'),
  ev(5025, SEC, 'Security', FW, 'Firewall service stopped', 'The Windows Firewall service was stopped.', 'Expected at shutdown. At any other time find out who stopped it.'),
  ev(5152, SEC, 'Security', FW, 'Packet blocked', 'The Windows Filtering Platform blocked a packet. Needs Audit Filtering Platform Packet Drop.', 'High volume. Use it to prove that the firewall drops specific traffic, then turn the auditing off again.'),
  ev(5154, SEC, 'Security', FW, 'Listening on a port permitted', 'The Windows Filtering Platform allowed a program to listen on a port for incoming connections.', 'Check the program and the port when looking for unexpected listeners.'),
  ev(5156, SEC, 'Security', FW, 'Connection allowed', 'The Windows Filtering Platform allowed a connection. The event holds the program, direction, addresses and ports. Needs Audit Filtering Platform Connection.', 'Very high volume. Filter by program or address to see what a process talks to.'),
  ev(5157, SEC, 'Security', FW, 'Connection blocked', 'The Windows Filtering Platform blocked a connection. The event holds the program, direction, addresses and ports.', 'Use it to find which program and port a firewall rule is blocking.'),
  ev(5158, SEC, 'Security', FW, 'Bind to a local port permitted', 'The Windows Filtering Platform allowed a program to bind to a local port.', 'High volume. Useful to see which program used a given port.'),
  ev(2004, FIREWALL, FIREWALL_LOG, FW, 'Firewall rule added', 'A rule was added to the Windows Firewall exception list. This log is on by default, unlike the Security log events 4946 to 4948.', 'Check the rule name, what it allows and the program that added it.'),
  ev(2005, FIREWALL, FIREWALL_LOG, FW, 'Firewall rule modified', 'A Windows Firewall rule was changed.', 'Check what the rule allows now and who changed it.'),
  ev(2006, FIREWALL, FIREWALL_LOG, FW, 'Firewall rule deleted', 'A Windows Firewall rule was deleted.', 'Check which rule was removed and by whom.'),

  // System log: startup and shutdown
  ev(41, KPOWER, 'System', BOOT, 'Restarted without a clean shutdown', 'The system restarted without shutting down cleanly first: a power loss, a hard reset, a hang or a crash. Logged at the next boot.', 'Read BugcheckCode in the event data. Not zero means a stop error: look for event 1001 and the memory dump. Zero means power was lost or the machine was forced off: check the power supply, UPS, temperature and hypervisor.'),
  ev(42, KPOWER, 'System', BOOT, 'System is entering sleep', 'The system is going to sleep. The event gives the reason.', 'Useful when a machine sleeps unexpectedly. Check the power plan.'),
  ev(1, 'Microsoft-Windows-Power-Troubleshooter', 'System', BOOT, 'System resumed from sleep', 'The system returned from a low power state. The event holds the sleep and wake times and the wake source.', 'Read the wake source to find the device or timer that woke the computer.'),
  ev(12, KGENERAL, 'System', BOOT, 'Operating system started', 'The operating system started. The event holds the start time.', 'Use it as a boot marker.'),
  ev(13, KGENERAL, 'System', BOOT, 'Operating system shutting down', 'The operating system is shutting down. The event holds the shutdown time.', 'Its presence before a boot shows the shutdown was clean.'),
  ev(1074, 'User32', 'System', BOOT, 'Shutdown or restart requested', 'A process or user started a shutdown or restart. The event holds the process, the user, the reason and the comment.', 'This answers who or what restarted the server: an administrator, an installer or Windows Update.'),
  ev(1076, 'User32', 'System', BOOT, 'Reason given for an unexpected shutdown', 'A user entered a reason in the shutdown tracker after the computer came back from an unexpected shutdown.', 'Read it together with events 6008 and 41 from the same boot.'),
  ev(6005, 'EventLog', 'System', BOOT, 'Event Log service started', 'The Event Log service started, which happens at boot.', 'Use it as a boot marker.'),
  ev(6006, 'EventLog', 'System', BOOT, 'Event Log service stopped', 'The Event Log service stopped, which happens during a clean shutdown.', 'A boot (6005) without a 6006 before it means the shutdown was not clean.'),
  ev(6008, 'EventLog', 'System', BOOT, 'Previous shutdown was unexpected', 'Logged at boot when the last shutdown was not clean. The event holds the time the system was last known to be running.', 'Look for event 41 and a stop error (1001) around that time, then check power and hardware.'),
  ev(6009, 'EventLog', 'System', BOOT, 'Operating system version at boot', 'Logged at boot with the Windows version and build.', 'Use it as a boot marker.'),
  ev(6013, 'EventLog', 'System', BOOT, 'System uptime', 'Logged once a day with the uptime in seconds.', 'Divide by 86400 for days. A value that drops shows a restart in between.'),
  ev(1001, 'Microsoft-Windows-WER-SystemErrorReporting', 'System', BOOT, 'Restarted after a stop error', 'The computer restarted after a stop error (blue screen). The event holds the stop code, its four parameters and the path of the memory dump.', 'Look up the stop code, analyse the dump (WinDbg, !analyze -v) and check recently changed drivers and hardware.'),

  // System log: Service Control Manager
  ev(7000, SCM, 'System', SERVICES, 'Service failed to start', 'A service did not start. The event holds the service name and the error.', 'Read the error text: a logon failure points to the service account or its password, a missing file to the program path, a timeout to a slow or broken start.'),
  ev(7001, SCM, 'System', SERVICES, 'Service dependency failed', 'A service could not start because a service it depends on did not start.', 'Fix the dependency named in the event first.'),
  ev(7009, SCM, 'System', SERVICES, 'Service start timed out', 'The service did not connect to the Service Control Manager within the timeout, 30 seconds by default. Usually followed by 7000.', 'Common on a slow or heavily loaded boot. Check for a damaged program file or missing runtime, and consider delayed start for the service.'),
  ev(7011, SCM, 'System', SERVICES, 'Service did not respond', 'The Service Control Manager timed out while waiting for a service to answer a request. The service is hung or very slow.', 'Check the service process for a hang and the machine for resource pressure at that time.'),
  ev(7022, SCM, 'System', SERVICES, 'Service hung on starting', 'A service stayed in the starting state and did not finish.', 'Check the service\'s own log and what it waits for, such as a network resource or a database.'),
  ev(7023, SCM, 'System', SERVICES, 'Service terminated with an error', 'A service stopped and reported a Windows error. The event holds the error text.', 'Read the error text, then the service\'s own log.'),
  ev(7024, SCM, 'System', SERVICES, 'Service terminated with a service-specific error', 'A service stopped and reported an error number that the service itself defines.', 'Look the number up in the documentation or log of that service, not in the Windows error tables.'),
  ev(7026, SCM, 'System', SERVICES, 'Boot or system start driver failed to load', 'One or more drivers that start at boot did not load. The event lists them.', 'Often a leftover of removed software or hardware. It matters when the listed driver is needed.'),
  ev(7031, SCM, 'System', SERVICES, 'Service crashed, recovery action taken', 'A service ended unexpectedly. The event says how often it happened and which recovery action follows, such as a restart of the service.', 'Look in the Application log for event 1000 or 1026 at the same time to find the failing module.'),
  ev(7032, SCM, 'System', SERVICES, 'Service recovery action failed', 'The Service Control Manager tried the configured recovery action after a service crash, and that action failed.', 'Read the error in the event and check why the service cannot be restarted.'),
  ev(7034, SCM, 'System', SERVICES, 'Service terminated unexpectedly', 'A service ended unexpectedly. The event says how many times it has happened.', 'Look in the Application log for event 1000 or 1026 at the same time. Set recovery actions for the service if it should restart.'),
  ev(7036, SCM, 'System', SERVICES, 'Service changed state', 'A service entered the running or stopped state. Informational.', 'Use it to build a timeline of when a service started and stopped.'),
  ev(7040, SCM, 'System', SERVICES, 'Service start type changed', 'The start type of a service was changed, for example from automatic to disabled.', 'The event names the user. Check who disabled or enabled the service and why.'),
  ev(7045, SCM, 'System', SERVICES, 'Service installed', 'A new service was installed. The event holds the service name, file path, service type, start type and account.', 'Check unknown services, above all with a path in a temp or user folder or a command line that runs cmd or PowerShell. Remote tools install services too, PsExec for example creates PSEXESVC.'),

  // System log: logs, DCOM, network and domain
  ev(104, EVENTLOG, 'System', AUDIT, 'Event log cleared', 'An event log other than Security, such as System or Application, was cleared. The event names the log and the user.', 'Confirm it was planned. The Security log has its own event, 1102.'),
  ev(10016, DCOM, 'System', NETWORK, 'DCOM permission denied', 'An account does not have permission to launch or activate a COM server. The event names the CLSID, the APPID and the account.', 'Very common and usually harmless on current Windows versions. Microsoft advises leaving it alone when nothing is broken.'),
  ev(10010, DCOM, 'System', NETWORK, 'COM server did not register in time', 'A COM server was started but did not register with DCOM within the timeout.', 'Find the CLSID in the registry to identify the program. Usually a slow or hung service or application.'),
  ev(1014, 'Microsoft-Windows-DNS-Client', 'System', NETWORK, 'DNS name resolution timed out', 'Resolving a name timed out because none of the configured DNS servers answered.', 'Check the DNS servers set on the adapter and whether they were reachable at that time. Often seen right after boot or wake, before the network is up.'),
  ev(5719, 'NETLOGON', 'System', NETWORK, 'No domain controller reachable', 'The computer could not set up a secure session with a domain controller of its domain.', 'At boot it often only means the network was not ready yet. Otherwise check that the DNS settings point to the domain DNS servers and that the domain controllers are reachable.'),
  ev(3210, 'NETLOGON', 'System', NETWORK, 'Secure channel authentication failed', 'The computer failed to authenticate with a domain controller. Its computer account password no longer matches the domain, known as a broken trust relationship.', 'Repair the secure channel with Test-ComputerSecureChannel -Repair, or rejoin the domain.'),
  ev(1030, GP, 'System', NETWORK, 'Group Policy processing failed', 'Windows could not retrieve new Group Policy settings for the user or computer. The Details tab holds the error code.', 'Look for another event at the same time that names the cause, such as 1058 or 1129. Then run gpupdate /force and gpresult /h report.html.'),
  ev(1058, GP, 'System', NETWORK, 'Group Policy file could not be read', 'Group Policy processing failed because the gpt.ini file of a policy could not be read from SYSVOL on a domain controller.', 'Check access to \\\\domain\\SYSVOL from the client, DNS, and SYSVOL replication between domain controllers. The Details tab holds the error code.'),
  ev(1129, GP, 'System', NETWORK, 'Group Policy failed, no domain controller', 'Group Policy processing failed because there was no network connectivity to a domain controller.', 'Often transient at boot or on VPN clients. If it persists check DNS and connectivity to the domain controllers.'),
  ev(4, 'Microsoft-Windows-Security-Kerberos', 'System', NETWORK, 'Kerberos ticket could not be decrypted by the server', 'The Kerberos client received a KRB_AP_ERR_MODIFIED error: the target server could not decrypt the ticket, because the ticket was issued for another account than the one the service runs as.', 'Look for a duplicate or misplaced service principal name (setspn -X), a DNS record that points the name to another machine, or a computer account password out of sync.'),
  ev(36871, 'Schannel', 'System', NETWORK, 'TLS credential could not be created', 'A fatal error occurred while creating a TLS client or server credential.', 'Often caused by disabled protocols or cipher suites that leave nothing usable, or by a certificate whose private key cannot be accessed.'),
  ev(36874, 'Schannel', 'System', NETWORK, 'No common TLS cipher suite', 'A remote client asked for a TLS connection, but the server supports none of the cipher suites the client offered. The connection failed.', 'Compare the cipher suites and protocol versions enabled on both sides. Old clients against a hardened server are the usual cause.'),
  ev(36887, 'Schannel', 'System', NETWORK, 'Fatal TLS alert received', 'The remote endpoint sent a fatal TLS alert. The event holds the alert code defined by the TLS protocol.', 'Look up the alert code: 40 handshake failure, 46 certificate unknown, 48 unknown CA, 70 protocol version.'),
  ev(36888, 'Schannel', 'System', NETWORK, 'Fatal TLS alert sent', 'This computer generated a fatal TLS alert and sent it to the remote endpoint. The event holds the alert code and an internal error state.', 'Look up the alert code: 40 handshake failure, 46 certificate unknown, 48 unknown CA, 70 protocol version. Then compare protocols, cipher suites and certificates on both sides.'),

  // System log: disk and hardware
  ev(7, 'disk', 'System', HARDWARE, 'Bad block on disk', 'A disk reported a bad block.', `${DISK_CHECK} A disk that logs this repeatedly should be replaced.`),
  ev(11, 'disk', 'System', HARDWARE, 'Disk controller error', 'The disk driver detected a controller error on a device.', DISK_CHECK),
  ev(51, 'disk', 'System', HARDWARE, 'Error during a paging operation', 'An error was detected on a disk during a paging operation, that is while reading or writing memory pages.', `${DISK_CHECK} Also seen with removable media and storage path problems.`),
  ev(153, 'disk', 'System', HARDWARE, 'Disk I/O was retried', 'An I/O request to a disk did not complete in time and was retried.', 'A sign of timeouts on the storage path. On virtual machines check the latency of the host storage, on physical machines the disk and cables.'),
  ev(157, 'disk', 'System', HARDWARE, 'Disk was surprise removed', 'A disk disappeared without being removed safely.', 'Expected for an unplugged USB drive. For internal or SAN disks check cables, power and the storage path.'),
  ev(55, 'Ntfs', 'System', HARDWARE, 'File system corruption', 'The file system structure on a volume is corrupt. The event names the volume.', 'Run chkdsk /f on the volume, then check the health of the disk underneath. Make sure a good backup exists.'),
  ev(129, 'storahci', 'System', HARDWARE, 'Storage device reset', 'A request to a storage device timed out and the driver reset the device. I/O stalls while this happens, which shows as a freeze. The source is the storage driver in use: storahci, stornvme, storvsc or a vendor driver.', 'Check the disk or SSD firmware, cables, the controller driver and link power management. On virtual machines check storage latency on the host.'),
  ev(17, WHEA, 'System', HARDWARE, 'Corrected hardware error', 'The hardware reported an error that was corrected. The event names the component and the error source.', 'A few are tolerable, a steady stream is not. Update firmware and drivers for the named component and watch whether the count grows.'),
  ev(18, WHEA, 'System', HARDWARE, 'Fatal hardware error', 'The hardware reported a fatal error, such as a machine check exception. The event names the reporting component.', 'Treat as a hardware fault: check CPU, memory, temperature and power, update the firmware, and run the vendor diagnostics.'),
  ev(19, WHEA, 'System', HARDWARE, 'Corrected hardware error', 'The hardware reported an error that was corrected. The event names the component and the error source.', 'A few are tolerable, a steady stream is not. Update the firmware and watch whether the count grows.'),

  // System log: Windows Update
  ev(19, WU, 'System', UPDATE, 'Update installed', 'Windows Update installed an update successfully. The event names the update.', 'Use it to confirm when a specific update was installed.'),
  ev(20, WU, 'System', UPDATE, 'Update installation failed', 'Windows Update failed to install an update. The event holds the error code and the update name.', 'Look up the error code, then read CBS.log and the Windows Update log (Get-WindowsUpdateLog).'),
  ev(43, WU, 'System', UPDATE, 'Update installation started', 'Windows Update started installing an update.', 'Pair it with event 19 or 20 for the result.'),
  ev(44, WU, 'System', UPDATE, 'Update download started', 'Windows Update started downloading an update.', 'If no install follows, check the download for errors.'),

  // Application log
  ev(1000, 'Application Error', 'Application', APPS, 'Application crashed', 'A program crashed. The event names the faulting application, the faulting module, the exception code and the offset.', 'Read the exception code (0xc0000005 is an access violation) and the faulting module. A third-party module often points to the cause. Event 1001 that follows holds the report details.'),
  ev(1001, 'Windows Error Reporting', 'Application', APPS, 'Error report details', 'Windows Error Reporting recorded a problem report: the fault bucket, the event name and the files attached.', 'Pair it with the 1000 or 1002 event just before it. The listed paths can hold a crash dump.'),
  ev(1002, 'Application Hang', 'Application', APPS, 'Application stopped responding', 'A program stopped responding and was closed.', 'Check what the program was waiting for: a network share, a database, a printer or a busy disk.'),
  ev(1026, '.NET Runtime', 'Application', APPS, 'Unhandled .NET exception', 'A .NET program ended because of an unhandled exception. The event holds the exception type and the stack trace.', 'Read the exception type and the first frames of the stack. Usually followed by event 1000 for the same process.'),
  ev(2004, 'Microsoft-Windows-Resource-Exhaustion-Detector', 'System', APPS, 'Low virtual memory', 'Windows diagnosed a low virtual memory condition. The event lists the processes that used the most virtual memory.', 'Check the listed processes for a memory leak and review the page file size.'),
  ev(1033, 'MsiInstaller', 'Application', APPS, 'Product installed, with status', 'Windows Installer finished installing a product. The event holds the product name, version, manufacturer and a status, 0 for success.', 'A status other than 0 is a Windows Installer error such as 1603. Run the installer with msiexec /l*v log.txt and search the log for "Return value 3".'),
  ev(1034, 'MsiInstaller', 'Application', APPS, 'Product removed, with status', 'Windows Installer finished removing a product. The event holds the product name, version and a status, 0 for success.', 'Use it to see when software was uninstalled and whether it succeeded.'),
  ev(11707, 'MsiInstaller', 'Application', APPS, 'Product installed successfully', 'Windows Installer completed the installation of a product.', 'Use it to see when software was installed. The event names the user.'),
  ev(11708, 'MsiInstaller', 'Application', APPS, 'Product installation failed', 'Windows Installer could not install a product.', 'Run the installer with msiexec /l*v log.txt and search the log for "Return value 3" to find the failing step.'),
  ev(11724, 'MsiInstaller', 'Application', APPS, 'Product removed successfully', 'Windows Installer completed the removal of a product.', 'Use it to see when software was uninstalled and by whom.'),
  ev(1511, 'Microsoft-Windows-User Profiles Service', 'Application', APPS, 'Temporary profile used', 'Windows could not find or load the local profile of the user and logged them on with a temporary profile. Changes in it are lost at logoff.', 'Check the profile folder and the ProfileList registry key for an entry ending in .bak, and check free disk space.'),
  ev(1530, 'Microsoft-Windows-User Profiles Service', 'Application', APPS, 'Registry still in use at logoff', 'At logoff the user registry was still in use by other programs or services. Windows unloaded it anyway. The event lists the processes.', 'Usually harmless. Frequent entries for the same process point to a program that leaks registry handles.'),
  ev(18456, 'MSSQLSERVER', 'Application', APPS, 'SQL Server login failed', 'A login to SQL Server failed. The event holds the login name and the client address. The source is MSSQLSERVER for the default instance and MSSQL$name for a named instance.', 'The State number in the SQL Server error log gives the exact reason. Many failures for sa from outside addresses are password guessing.'),

  // PowerShell
  ev(4103, PS, PS_LOG, POWERSHELL, 'Module logging', 'Records the commands that ran and their parameters. Logged only when the module logging policy is on.', 'Search the payload for suspicious commands such as downloads or encoded input.'),
  ev(4104, PS, PS_LOG, POWERSHELL, 'Script block logging', 'Records the text of script blocks as PowerShell runs them. Full logging needs the script block logging policy, but blocks that look suspicious are logged as warnings even without it.', 'Read the script text. Long scripts are split over several events with the same script block ID.'),
  ev(400, 'PowerShell', PS_CLASSIC_LOG, POWERSHELL, 'Engine started', 'A PowerShell engine started. The event holds the host name, the engine version and the command line of the host application.', 'The host application shows how PowerShell was started. Engine version 2.0 on a current system is a downgrade that avoids script block logging.'),
  ev(403, 'PowerShell', PS_CLASSIC_LOG, POWERSHELL, 'Engine stopped', 'A PowerShell engine stopped.', 'Pair it with event 400 to see how long a session ran.'),
  ev(600, 'PowerShell', PS_CLASSIC_LOG, POWERSHELL, 'Provider started', 'A PowerShell provider, such as Registry or FileSystem, started. Several are logged each time a session starts.', 'Like event 400, it holds the command line of the host application.'),
  ev(800, 'PowerShell', PS_CLASSIC_LOG, POWERSHELL, 'Pipeline execution details', 'Records the details of an executed pipeline. Logged when module logging is on.', 'Search the details for the commands that ran and their parameters.'),

  // Remote Desktop
  ev(1149, RCM, RCM_LOG, RDP, 'Remote Desktop connection authenticated', 'A Remote Desktop connection reached the server. The event holds the user name, the domain and the source address.', 'Use it for the source address of Remote Desktop connections. On its own it does not prove a completed logon: confirm with event 21 or a 4624 with logon type 10.'),
  ev(261, RCM, RCM_LOG, RDP, 'Listener received a connection', 'The Remote Desktop listener received a connection, before any authentication.', 'Many of these without logons that follow suggest port scans or password guessing against Remote Desktop.'),
  ev(131, 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS', 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational', RDP, 'Connection accepted from a client', 'The Remote Desktop server accepted a new network connection. The event holds the client address and port.', 'Use it to find the client address of a connection attempt, even when no logon followed.'),
  ev(21, LSM, LSM_LOG, RDP, 'Session logon succeeded', 'A user logged on to a session. The event holds the user, the session ID and the source address. The address reads LOCAL for a console logon.', 'This is the clearest record of who opened a Remote Desktop session from where.'),
  ev(22, LSM, LSM_LOG, RDP, 'Shell started', 'The shell (desktop) started for a session. Follows event 21.', 'Routine. Confirms the session reached the desktop.'),
  ev(23, LSM, LSM_LOG, RDP, 'Session logoff succeeded', 'A user logged off and the session ended.', 'Pair it with event 21 for the session length.'),
  ev(24, LSM, LSM_LOG, RDP, 'Session disconnected', 'A session was disconnected. The user is still logged on and programs keep running.', 'Check the source address. Sessions left disconnected hold resources and credentials.'),
  ev(25, LSM, LSM_LOG, RDP, 'Session reconnected', 'A user reconnected to an existing session. The event holds the source address.', 'Check that the address is one the user normally connects from.'),
  ev(39, LSM, LSM_LOG, RDP, 'Session disconnected by another session', 'A session was disconnected by another session, for example when a user disconnects through the Start menu or an administrator disconnects them.', 'The two session IDs show whether the user or someone else caused the disconnect.'),
  ev(40, LSM, LSM_LOG, RDP, 'Session disconnected, with reason code', 'A session was disconnected. The event holds a reason code.', 'Look up the reason code to tell a user action from a network drop or a logon from another place.'),

  // Task Scheduler
  ev(100, TASKS, TASKS_LOG, SCHEDULER, 'Task started', 'Task Scheduler started an instance of a task.', TASK_HISTORY),
  ev(101, TASKS, TASKS_LOG, SCHEDULER, 'Task start failed', 'Task Scheduler could not start a task. The event holds the error.', 'Read the error value. A logon failure points to the account or password stored for the task.'),
  ev(102, TASKS, TASKS_LOG, SCHEDULER, 'Task completed', 'A task instance finished.', 'Completed does not mean the program succeeded. Read the return code in event 201.'),
  ev(106, TASKS, TASKS_LOG, SCHEDULER, 'Task registered', 'A new task was created. The event names the task and the user.', 'Check unexpected tasks: what they run and as which account.'),
  ev(107, TASKS, TASKS_LOG, SCHEDULER, 'Task triggered on schedule', 'Task Scheduler started a task because its time trigger fired.', 'If it is missing at the expected time, the trigger did not fire: check the trigger and whether the machine was on.'),
  ev(110, TASKS, TASKS_LOG, SCHEDULER, 'Task triggered by user', 'A user started a task manually.', 'The event names the user.'),
  ev(111, TASKS, TASKS_LOG, SCHEDULER, 'Task terminated', 'Task Scheduler ended a running task instance, on request or because of a task setting.', 'Check the task settings for a run time limit.'),
  ev(129, TASKS, TASKS_LOG, SCHEDULER, 'Task process created', 'Task Scheduler launched the program of a task. The event holds the program and the process ID.', 'Use the process ID to follow the program in other logs.'),
  ev(140, TASKS, TASKS_LOG, SCHEDULER, 'Task updated', 'The definition of a task was changed. The event names the task and the user.', 'Check what the task runs now.'),
  ev(141, TASKS, TASKS_LOG, SCHEDULER, 'Task deleted', 'A task was deleted. The event names the task and the user.', 'Check who removed it, above all for backup and maintenance tasks.'),
  ev(200, TASKS, TASKS_LOG, SCHEDULER, 'Action started', 'Task Scheduler started an action of a task. The event names the program.', TASK_HISTORY),
  ev(201, TASKS, TASKS_LOG, SCHEDULER, 'Action completed', 'An action of a task finished. The event holds the return code of the program.', 'Return code 0 means the program reported success. Any other value comes from the program itself, so look it up there.'),

  // Windows Defender
  ev(1000, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Scan started', 'An antimalware scan started. The event holds the scan type.', 'Routine. Pair it with 1001 or 1002 for the outcome.'),
  ev(1001, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Scan finished', 'An antimalware scan finished.', 'Routine. Detections are logged separately as 1116.'),
  ev(1002, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Scan stopped before finishing', 'An antimalware scan was stopped before it completed.', 'Check whether a user cancelled it or the machine shut down.'),
  ev(1006, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Malware found by a scan', 'The antimalware engine found malware or other potentially unwanted software.', 'Read the threat name and the path, then check which action followed (1007 or 1008).'),
  ev(1007, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Action taken against malware', 'The antimalware engine took an action, such as quarantine or remove, on a detected item.', 'Check the action and whether it succeeded, then find out how the file arrived.'),
  ev(1008, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Action against malware failed', 'The antimalware engine tried to act on a detected item and failed.', 'The threat may still be present. Read the error and run a full or offline scan.'),
  ev(1116, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Malware detected', 'The antimalware platform detected malware or other potentially unwanted software. The event holds the threat name, severity, path, process and user.', 'Read the threat name, the path and the process that touched the file. Event 1117 shows the action taken.'),
  ev(1117, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Protective action taken', 'The antimalware platform took an action to protect the system from a detected threat.', 'Check that the action was quarantine or remove and that it succeeded.'),
  ev(1118, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Protective action failed', 'The antimalware platform tried to act on a detected threat and failed.', 'The threat may still be present. Read the error and scan again.'),
  ev(1119, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Protective action failed critically', 'The antimalware platform hit a critical error while acting on a detected threat.', 'Treat the machine as possibly infected. Run an offline scan and investigate.'),
  ev(2000, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Definitions updated', 'The antimalware definitions were updated successfully. The event holds the old and new version.', 'Routine. Use it to confirm definitions are current.'),
  ev(2001, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Definition update failed', 'An update of the antimalware definitions failed. The event holds the error code.', 'Look up the error code and check access to the update source (Windows Update, WSUS or a file share).'),
  ev(3002, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Real-time protection failed', 'A real-time protection feature hit an error and failed.', 'Read the error. Protection may be reduced until the feature recovers or the machine restarts.'),
  ev(5000, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Real-time protection enabled', 'Real-time protection was turned on.', 'Routine. Look for a 5001 before it to see how long protection was off.'),
  ev(5001, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Real-time protection disabled', 'Real-time protection was turned off.', 'Find out who or what turned it off. Malware and attackers do this before running their tools. Another antivirus product taking over is a harmless reason.'),
  ev(5004, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Real-time protection configuration changed', 'The configuration of a real-time protection feature changed.', 'Check which feature and value changed.'),
  ev(5007, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Configuration changed', 'The antimalware configuration changed. The event holds the old and new value of the setting.', 'Look for new exclusions (paths, extensions, processes) and disabled features. Attackers add exclusions to hide their files.'),
  ev(5010, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Antispyware scanning disabled', 'Scanning for malware and other potentially unwanted software was turned off.', 'Find out who or what turned it off.'),
  ev(5012, DEFENDER, DEFENDER_LOG, ANTIVIRUS, 'Antivirus scanning disabled', 'Scanning for viruses was turned off.', 'Find out who or what turned it off.'),
];

export interface CodeRow {
  code: string;
  name: string;
  meaning: string;
}

/** Logon Type field of events 4624, 4625 and 4634. */
export const LOGON_TYPES: CodeRow[] = [
  { code: '2', name: 'Interactive', meaning: 'Logon at the console: keyboard and screen, or a hypervisor or KVM console.' },
  { code: '3', name: 'Network', meaning: 'Access over the network, such as a file share, a remote management call or the first step of a Remote Desktop logon with Network Level Authentication.' },
  { code: '4', name: 'Batch', meaning: 'A scheduled task ran as the account.' },
  { code: '5', name: 'Service', meaning: 'A service was started under the account by the Service Control Manager.' },
  { code: '7', name: 'Unlock', meaning: 'A locked workstation was unlocked.' },
  { code: '8', name: 'NetworkCleartext', meaning: 'A network logon where the password arrived in clear text, such as IIS basic authentication.' },
  { code: '9', name: 'NewCredentials', meaning: 'A process kept its local identity but uses other credentials for network connections, as runas /netonly does.' },
  { code: '10', name: 'RemoteInteractive', meaning: 'Logon through Remote Desktop.' },
  { code: '11', name: 'CachedInteractive', meaning: 'Console logon with cached domain credentials. No domain controller was contacted.' },
  { code: '12', name: 'CachedRemoteInteractive', meaning: 'Remote Desktop logon with cached domain credentials.' },
  { code: '13', name: 'CachedUnlock', meaning: 'Unlock with cached domain credentials.' },
];

/** Status and Sub Status of event 4625. Event 4776 uses the same values as its error code. */
export const LOGON_FAILURE_CODES: CodeRow[] = [
  { code: '0xC000005E', name: 'STATUS_NO_LOGON_SERVERS', meaning: 'No domain controller was available to check the logon.' },
  { code: '0xC0000064', name: 'STATUS_NO_SUCH_USER', meaning: 'The user name does not exist.' },
  { code: '0xC000006A', name: 'STATUS_WRONG_PASSWORD', meaning: 'The user name is correct but the password is wrong.' },
  { code: '0xC000006D', name: 'STATUS_LOGON_FAILURE', meaning: 'Bad user name or authentication information. A general status, the Sub Status usually gives the detail.' },
  { code: '0xC000006E', name: 'STATUS_ACCOUNT_RESTRICTION', meaning: 'An account restriction prevented the logon, for example a blank password used over the network.' },
  { code: '0xC000006F', name: 'STATUS_INVALID_LOGON_HOURS', meaning: 'The logon is outside the hours allowed for the account.' },
  { code: '0xC0000070', name: 'STATUS_INVALID_WORKSTATION', meaning: 'The account is not allowed to log on from this workstation.' },
  { code: '0xC0000071', name: 'STATUS_PASSWORD_EXPIRED', meaning: 'The password has expired.' },
  { code: '0xC0000072', name: 'STATUS_ACCOUNT_DISABLED', meaning: 'The account is disabled.' },
  { code: '0xC0000133', name: 'STATUS_TIME_DIFFERENCE_AT_DC', meaning: 'The clocks of the client and the domain controller are too far apart.' },
  { code: '0xC000015B', name: 'STATUS_LOGON_TYPE_NOT_GRANTED', meaning: 'The account has not been granted this type of logon on the computer, for example Remote Desktop or logon as a service.' },
  { code: '0xC000018C', name: 'STATUS_TRUSTED_DOMAIN_FAILURE', meaning: 'The trust relationship between this domain and the trusted domain failed.' },
  { code: '0xC0000192', name: 'STATUS_NETLOGON_NOT_STARTED', meaning: 'The Netlogon service is not running.' },
  { code: '0xC0000193', name: 'STATUS_ACCOUNT_EXPIRED', meaning: 'The account has expired.' },
  { code: '0xC0000224', name: 'STATUS_PASSWORD_MUST_CHANGE', meaning: 'The user must change the password before logging on.' },
  { code: '0xC0000234', name: 'STATUS_ACCOUNT_LOCKED_OUT', meaning: 'The account is locked out.' },
  { code: '0xC0000413', name: 'STATUS_AUTHENTICATION_FIREWALL_FAILED', meaning: 'The account is not allowed to authenticate to this computer, as with selective authentication across a trust.' },
];

/** Result and failure codes of events 4768, 4769 and 4771. */
export const KERBEROS_FAILURE_CODES: CodeRow[] = [
  { code: '0x6', name: 'KDC_ERR_C_PRINCIPAL_UNKNOWN', meaning: 'The user name does not exist in the domain.' },
  { code: '0x7', name: 'KDC_ERR_S_PRINCIPAL_UNKNOWN', meaning: 'The service name (SPN) was not found in the domain.' },
  { code: '0xC', name: 'KDC_ERR_POLICY', meaning: 'The request was refused by policy, such as a workstation or logon hours restriction.' },
  { code: '0xE', name: 'KDC_ERR_ETYPE_NOSUPP', meaning: 'Client, account and domain controller share no supported encryption type.' },
  { code: '0x12', name: 'KDC_ERR_CLIENT_REVOKED', meaning: 'The account is disabled, expired or locked out.' },
  { code: '0x17', name: 'KDC_ERR_KEY_EXPIRED', meaning: 'The password has expired.' },
  { code: '0x18', name: 'KDC_ERR_PREAUTH_FAILED', meaning: 'The password is wrong.' },
  { code: '0x19', name: 'KDC_ERR_PREAUTH_REQUIRED', meaning: 'The client sent no pre-authentication data. A normal first step for many clients, not a failure on its own.' },
  { code: '0x20', name: 'KRB_AP_ERR_TKT_EXPIRED', meaning: 'The ticket has expired.' },
  { code: '0x25', name: 'KRB_AP_ERR_SKEW', meaning: 'The clocks of the client and the domain controller differ too much, more than five minutes by default.' },
];

const LOGON_TYPE_EVENTS = [4624, 4625, 4634];
const LOGON_FAILURE_EVENTS = [4625, 4776];
const KERBEROS_EVENTS = [4768, 4769, 4771];

/** Which reference tables help to read the given events. */
export function referenceTablesFor(events: WindowsEvent[]): { logonTypes: boolean; logonFailureCodes: boolean; kerberosCodes: boolean } {
  const security = events.filter(event => event.source === SEC).map(event => event.id);
  return {
    logonTypes: security.some(id => LOGON_TYPE_EVENTS.includes(id)),
    logonFailureCodes: security.some(id => LOGON_FAILURE_EVENTS.includes(id)),
    kerberosCodes: security.some(id => KERBEROS_EVENTS.includes(id)),
  };
}

export interface EventFilters {
  log?: string;
  category?: string;
}

/** The event ID when the query is a number, with an optional "event", "id" or "event id" in front. */
export function parseEventId(query: string): number | null {
  const match = /^(?:event\s*)?(?:id\s*)?[:#]?\s*(\d{1,5})$/i.exec(query.trim());
  return match ? Number(match[1]) : null;
}

function byId(a: WindowsEvent, b: WindowsEvent): number {
  return a.id - b.id || a.source.localeCompare(b.source);
}

/**
 * A number returns the events with exactly that ID (every source). When the
 * reference has no such ID, IDs that start with those digits are returned
 * instead. Any other text is a keyword search: every word must occur in the
 * title, meaning, category, source or log, and events that match in more of
 * those places rank higher. An empty query returns everything that passes the
 * filters.
 */
export function searchEvents(query: string, filters: EventFilters = {}): WindowsEvent[] {
  const pool = WINDOWS_EVENTS.filter(event => (!filters.log || event.log === filters.log) && (!filters.category || event.category === filters.category));
  const text = query.trim();
  if (!text) return [...pool].sort(byId);

  const id = parseEventId(text);
  if (id !== null) {
    const exact = pool.filter(event => event.id === id);
    if (exact.length) return exact.sort(byId);
    return pool.filter(event => String(event.id).startsWith(String(id))).sort(byId);
  }

  const words = text.toLowerCase().split(/\s+/);
  const scored: Array<{ event: WindowsEvent; score: number }> = [];
  for (const event of pool) {
    const title = event.title.toLowerCase();
    const names = `${event.category} ${event.source} ${event.log}`.toLowerCase();
    const meaning = event.meaning.toLowerCase();
    let score = 0;
    for (const word of words) {
      const hit = (String(event.id) === word || title.includes(word) ? 3 : 0) + (names.includes(word) ? 2 : 0) + (meaning.includes(word) ? 1 : 0);
      if (hit === 0) { score = 0; break; }
      score += hit;
    }
    if (score > 0) scored.push({ event, score });
  }
  return scored.sort((a, b) => b.score - a.score || byId(a.event, b.event)).map(item => item.event);
}

export interface CategoryCount {
  category: string;
  count: number;
}

/** Categories in the order they first appear in the dataset, with the number of events in each. */
export function eventCategories(): CategoryCount[] {
  const counts = new Map<string, number>();
  for (const event of WINDOWS_EVENTS) counts.set(event.category, (counts.get(event.category) ?? 0) + 1);
  return [...counts].map(([category, count]) => ({ category, count }));
}

/** Distinct log (channel) names, classic logs first. */
export function eventLogs(): string[] {
  const classic = ['Security', 'System', 'Application'];
  const others = [...new Set(WINDOWS_EVENTS.map(event => event.log))].filter(log => !classic.includes(log)).sort();
  return [...classic, ...others];
}

export interface EventCommands {
  powershell: string;
  wevtutil: string;
}

/** Commands that list the most recent occurrences of the event on a machine. */
export function eventCommands(event: Pick<WindowsEvent, 'id' | 'log'>): EventCommands {
  return {
    powershell: `Get-WinEvent -FilterHashtable @{LogName=${psQuote(event.log)}; Id=${event.id}} -MaxEvents 50`,
    wevtutil: `wevtutil qe ${cmdQuote(event.log)} "/q:*[System[(EventID=${event.id})]]" /c:10 /rd:true /f:text`,
  };
}
