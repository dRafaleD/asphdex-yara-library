rule ASPL_Defender_Realtime_Disable
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1562/001/"
        license = "ISC"
        description = "Defender preference explicitly disables realtime monitoring"
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
        $anchor = "Set-MpPreference" ascii wide nocase
        $chain = /Set-MpPreference[ \t]+-DisableRealtimeMonitoring[ \t]+\$true/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
