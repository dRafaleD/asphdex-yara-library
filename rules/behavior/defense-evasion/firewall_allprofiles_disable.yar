rule ASPL_Firewall_AllProfiles_Disable
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1562/004/"
        license = "ISC"
        description = "Netsh disables all Windows firewall profiles"
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
        $anchor = "advfirewall" ascii wide nocase
        $chain = /netsh(\.exe)?[ \t]+advfirewall[ \t]+set[ \t]+allprofiles[ \t]+state[ \t]+off([ \t\r\n]|$)/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
