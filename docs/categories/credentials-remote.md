# Credentials, collection and remote access

These 20 original experimental rules describe narrow static artifacts. They are not malware-family signatures, execution evidence, theft verdicts or probability estimates. ATT&CK links describe technique context; they do not endorse these rules or validate detection quality.

## Scope and review procedure

Each rule requires an anchor and every other contextual marker in the 4096-byte window following one occurrence of that anchor, in a file no larger than 2 MiB. ASCII and UTF-16LE spellings are matched case-insensitively. Offset association limits accidental combinations in unrelated file regions, but does not establish semantic relationship, command sequencing, data flow or execution. No imports, includes, private rules or global rules are used. Larger files, compressed archives, obfuscation and variant spelling are excluded.

Native compatibility means yara-python / libyara 4.5.0 or newer and YARA-X. The AsphDex JavaScript fallback does not support count/offset loop conditions and is outside this compatibility claim; it must report unsupported/limited coverage rather than implying a full scan.

Inspect matched bytes and the originating file type first. Determine whether these are source code, copied instructions, reference documentation or compiled strings. Establish authorized purpose and runtime evidence separately. Severity records potential impact if the action occurs; low/medium confidence describes only this artifact. Collection rules use existing AsphDex categories input-capture/scripted-execution rather than inventing an incompatible collection category.

## Known exact-document positives

Every positive fixture is deliberately an inert REFERENCE DOCUMENT ONLY text document. The screenshot, credential API, keyboard hook and WinRM examples explicitly demonstrate reference-document matches. These exact-document positives remain expected matches; never present them as malicious samples. The negative fixtures omit a required component, demonstrate a nearby benign operation, or separate a required marker from the anchor by 8192 bytes. They do not establish a false-positive rate. A complete legitimate backup, screenshot, diagnostic or remoting script can match. Fixture pass rates measure the written predicates, not real-world sensitivity or precision.

## Rules and authoritative technique context

| Rule | ATT&CK context | Specific limitation |
| --- | --- | --- |
| `ASPL_Comsvcs_Lsass_Dump_Context` | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Comsvcs LSASS dump context; authorized diagnostics and copied instructions can match. |
| `ASPL_Procdump_Lsass_Full_Dump` | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Full LSASS dump request text; incident-response and diagnostic use can match. |
| `ASPL_Sam_System_Hive_Export` | [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Paired SAM and SYSTEM hive-export text; authorized backup can match. |
| `ASPL_Chromium_Login_Database_Query` | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Exact Chromium password query spelling; maintenance, research and documentation can match. |
| `ASPL_Wifi_Profile_Clear_Key_Export` | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Clear-key wireless-profile export text; migration and support can match. |
| `ASPL_Dpapi_Credential_Blob_Unprotect` | [T1555.004](https://attack.mitre.org/techniques/T1555/004/) | DPAPI unprotection plus credential-blob fields; legitimate credential tools and SDK reference can match. |
| `ASPL_Vault_Enumeration_Read_Chain` | [T1555.004](https://attack.mitre.org/techniques/T1555/004/) | Vault enumeration with retrieval capabilities; SDK references and credential management can match. |
| `ASPL_Git_Plaintext_Credentials_Read` | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Python-style Git credential-file read and enumeration; credential migration can match. |
| `ASPL_Clipboard_Text_Append_Log` | [T1115](https://attack.mitre.org/techniques/T1115/) | Clipboard read and file-value append artifacts; productivity scripts can match. |
| `ASPL_Dotnet_Screen_Png_Save` | [T1113](https://attack.mitre.org/techniques/T1113/) | Screen copying and PNG-saving artifacts; ordinary screenshot tools and reference examples can match. |
| `ASPL_Keyboard_Hook_Log_Write_Context` | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Keyboard hook, key naming and file-write capabilities; accessibility and sample code can match. |
| `ASPL_Recursive_Documents_Zip_Staging` | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Recursive document collection with ZIP staging; ordinary document backup can match. |
| `ASPL_System_Inventory_Json_Staging` | [T1082](https://attack.mitre.org/techniques/T1082/) | System inventory classes with JSON file staging; normal fleet inventory can match. |
| `ASPL_Mci_Audio_Record_Save` | [T1123](https://attack.mitre.org/techniques/T1123/) | MCI recording and saving source artifacts; audio applications and SDK reference can match. |
| `ASPL_Powershell_Remote_Session_Command` | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Remote session with a session-bound command block; authorized administration can match. |
| `ASPL_Ssh_Reverse_Forward_No_Command` | [T1572](https://attack.mitre.org/techniques/T1572/) | Reverse SSH forwarding without remote command; legitimate support and development can match. |
| `ASPL_Socat_Tcp_Interactive_Shell` | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | TCP bridge to a PTY shell artifact; authorized labs and recovery tools can match. |
| `ASPL_Netsh_Portproxy_External_Listen` | [T1572](https://attack.mitre.org/techniques/T1572/) | IPv4 port-proxy addition with any-address listener; network administration can match. |
| `ASPL_Rdp_Enable_And_Firewall_Group` | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | RDP-enable value with firewall enabling; deployment and support scripts can match. |
| `ASPL_Winrm_Wildcard_Trust_Configuration` | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Remoting setup with wildcard client trust; insecure administration config is not compromise evidence. |

## Safe validation

Generate only `.txt` fixtures from the JSON specification. Never execute fixture content. Destinations use reserved `.invalid` names or RFC 5737 documentation addresses. Match positives in UTF-8 and UTF-16LE and reject all listed negatives. Compile and scan with both libyara and YARA-X. For production tuning add an authorized corpus with full benign operations and exact reference documents, preserve known document positives in evaluation, and report their outcomes honestly.
