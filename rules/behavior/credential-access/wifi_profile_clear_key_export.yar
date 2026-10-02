// Original contextual static-artifact rule; references can match.
rule ASPL_Wifi_Profile_Clear_Key_Export
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1552/001/"
        license = "ISC"
        description = "Clear-key wireless-profile export text; migration and support can match."
        category = "credential-access"
        confidence = "medium"
        severity = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Clear-key wireless-profile export text; migration and support can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1552.001"
    strings:
        $artifact1 = "netsh wlan export profile" ascii wide nocase
        $artifact2 = "key=clear" ascii wide nocase
        $artifact3 = "folder=" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
