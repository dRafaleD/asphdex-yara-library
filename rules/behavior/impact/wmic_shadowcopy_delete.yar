rule ASPL_Wmic_Shadowcopy_Delete
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1490/"
        license = "ISC"
        description = "WMIC deletes shadow copies"
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
        $anchor = "shadowcopy" ascii wide nocase
        $chain = /wmic(\.exe)?[ \t]+shadowcopy[ \t]+delete([ \t\r\n]|$)/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
