rule ASPL_Startup_Executable_Copy
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1547/001/"
        license = "ISC"
        description = "Copy command places an executable in the Startup directory"
        category = "persistence"
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
        $anchor = "Programs\\Startup" ascii wide nocase
        $chain = /copy[ \t]+"?[^\r\n"]{1,128}\.exe"?[ \t]+"?[^\r\n"]{0,128}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\[^\r\n"]{1,64}\.exe/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
