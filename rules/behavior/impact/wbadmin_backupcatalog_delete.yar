rule ASPL_Wbadmin_BackupCatalog_Delete
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1490/"
        license = "ISC"
        description = "Backup catalog deletion suppresses confirmation"
        category = "impact"
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
        $anchor = "wbadmin" ascii wide nocase
        $chain = /wbadmin(\.exe)?[ \t]+delete[ \t]+catalog[ \t]+-quiet([ \t\r\n]|$)/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
