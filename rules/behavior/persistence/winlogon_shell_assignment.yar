rule ASPL_Winlogon_Shell_Assignment
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1547/004/"
        license = "ISC"
        description = "Winlogon Shell value is assigned an executable"
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
        $anchor = "Winlogon" ascii wide nocase
        $chain = /reg(\.exe)?[ \t]+add[ \t]+"?HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"?[^\r\n]{0,128}\/v[ \t]+Shell[^\r\n]{0,128}\/d[ \t]+"?[^\r\n"]{1,128}\.exe/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
