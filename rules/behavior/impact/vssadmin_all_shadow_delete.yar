rule ASPL_Vssadmin_All_Shadow_Delete
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1490/"
        license = "ISC"
        description = "Vssadmin deletes all shadow copies without confirmation"
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
        $anchor = "vssadmin" ascii wide nocase
        $chain = /vssadmin(\.exe)?[ \t]+delete[ \t]+shadows[ \t]+\/all[ \t]+\/quiet/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
