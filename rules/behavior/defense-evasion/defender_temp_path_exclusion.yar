rule ASPL_Defender_Temp_Path_Exclusion
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1562/001/"
        license = "ISC"
        description = "Defender exclusion targets a temporary-content directory"
        category = "defense-evasion"
        severity = "low"
        confidence = "low"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Bounded same-line command artifact only. Comments, quoted examples and legitimate administration may match. Execution and malicious intent are not proven."
        minimum_yara = "4.5.0"
    strings:
        $anchor = "Add-MpPreference" ascii wide nocase
        $chain = /Add-MpPreference[ \t]+-ExclusionPath[ \t]+['"]([^\r\n'"]{0,128}\\(Temp|Temporary Internet Files)\\[^\r\n'"]{0,128}|\$env:TEMP[^\r\n'"]{0,128})['"]/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
