# threat-hunting-scenario-tor
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Michelle-Logan/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "mysticlifter" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at `2025-06-09T20:32:52.2846641Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where FileName contains "tor"
| where InitiatingProcessAccountName == "mysticlifter"
| where DeviceName == "michelle-window"
| where Timestamp >= datetime(2025-06-09T20:32:52.2846641Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/6bd81f74-2176-42e2-9a79-93bfad9ac945)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `2025-06-09T20:32:35.7473869Z`, an employee on the "michelle-window" device ran the file `tor-browser-windows-x86_64-portable-14.5.3.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where ProcessCommandLine startswith "tor-browser-windows"
| where DeviceName == "michelle-window"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/47d76946-a17e-4e19-9356-9532bafd808b)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "mysticlifter" actually opened the TOR browser. There was evidence that they did open it at `2025-06-09T20:33:22.1034483Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName  == "michelle-window"
| where FileName has_any ("tor.exe", "firefox.exe", "start-tor-browser.exe", "Browser\firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
![image](https://github.com/user-attachments/assets/211f1117-b37d-4194-aaa8-978a2256f566)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the know tor ports.
At 3:33:51 PM on June 9, 2025, the device named michelle-window successfully established a connection to the remote IP address 195.246.230.153 on port 9001. The connection was initiated by the process tor.exe, located in the folder C:\Users\mysticlifter\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe, running under the user account mysticlifter. There were a few other connections to sites over 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "michelle-window"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
![image](https://github.com/user-attachments/assets/22a8fe6b-5d43-4d3e-94a7-eb60790e7e17)

---

## 🕒 Chronological Events

---

### 📅 2025-06-09 15:32:00

**Multiple files related to Tor are created on the desktop by user `mysticlifter`:**

- `tor.exe`  
- `tor.txt`  
- `Torbutton.txt`  
- `Tor-Launcher.txt`

*Likely the result of extraction or installation activity.*

---

### 📅 2025-06-09 15:32:00

**Process Created:**

- `tor-browser-windows-x86_64-portable-14.5.3.exe` is executed from the `Downloads` folder.

*Indicates the Tor Browser installer was run — most likely a silent install.*

---

### 📅 2025-06-09 15:32:52

**Multiple Tor-related files continue being copied and written to the user’s desktop, including:**

- `start-tor-browser.exe`  
- `tor-shopping-list.txt` *(possibly an attempt to mask or blend the Tor folder contents)*  
- `firefox.exe` and additional components *(e.g., `libmozglue.dll`, `torrc-defaults`)*

---

### 📅 2025-06-09 15:33:22

**Tor Browser Launched:**

- `firefox.exe` and `tor.exe` are both executed from within the Tor Browser directory.

*Confirms the browser was opened and possibly used.*

---

### 📅 2025-06-09 15:33:51

**Network Activity Detected:**

- Device `michelle-window` establishes a successful connection to IP `195.246.230.153` over port `9001`.
- This port is known to be associated with the **Tor network**.
- **Initiating process:** `tor.exe` from the desktop Tor directory.

*Confirms the system connected to the Tor network.*

---

### 📅 2025-06-09 15:33:52 and onward

**More Tor-related process activities observed:**

- Additional invocations of `tor.exe` and `firefox.exe`.
- Persistent folder activity and likely **use of Tor for anonymous browsing**.

---


## Summary

The user “mysticlifter” on the “michelle-window” device initiated and completed the installation of the Tor browser.  They proceeded to launch the browser, establish connections within the Tor network, and created various files related to Tor on their desktop, including a file named tor-shopping-list.txt.  This sequence of activities indicates that the user actively installed, configured, and used the Tor browser, likely for anonymous browsing purposes, with possible documentation in the form of the “shopping list” file.


---

## Response Taken

TOR usage was confirmed on the endpoint `michelle-window` by the user `mysticlifter`. The device was isolated, and the user's direct manager was notified.

---
