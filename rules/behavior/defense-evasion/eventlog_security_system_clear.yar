rule ASPL_EventLog_Security_System_Clear
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1070/001/"
        license = "ISC"
        description = "Event utility clears the Security or System log"
        category = "defense-evasion"
        severity = "medium"
        confidence = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Bounded same-line command artifact only. Comments, quoted examples and legitimate administration may match. Execution and malicious intent are not proven."
        minimum_yara = "4.5.0"
    strings:
        $anchor = "wevtutil" ascii wide nocase
        $chain = /wevtutil(\.exe)?[ \t]+(cl|clear-log)[ \t]+(Security|System)([ \t\r\n]|$)/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
