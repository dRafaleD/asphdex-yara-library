rule ASPL_BootRecovery_Disable_IgnoreFailures
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1490/"
        license = "ISC"
        description = "One command disables boot recovery and ignores boot failures"
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
        $anchor = "bcdedit" ascii wide nocase
        $chain = /bcdedit(\.exe)?[ \t]+\/set[ \t]+\{(default|current)\}[ \t]+recoveryenabled[ \t]+no[^\r\n]{0,128}bcdedit(\.exe)?[ \t]+\/set[ \t]+\{(default|current)\}[ \t]+bootstatuspolicy[ \t]+ignoreallfailures/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
