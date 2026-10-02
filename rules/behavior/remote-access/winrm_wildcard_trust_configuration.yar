// Original contextual static-artifact rule; references can match.
rule ASPL_Winrm_Wildcard_Trust_Configuration
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1021/006/"
        license = "ISC"
        description = "Remoting setup with wildcard client trust; insecure administration config is not compromise evidence."
        category = "remote-access"
        confidence = "low"
        severity = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Remoting setup with wildcard client trust; insecure administration config is not compromise evidence. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1021.006"
    strings:
        $artifact1 = "Enable-PSRemoting" ascii wide nocase
        $artifact2 = "WSMan:\\localhost\\Client\\TrustedHosts" ascii wide nocase
        $artifact3 = "-Value \"*\"" ascii wide nocase
        $artifact4 = "Set-Item" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact4 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
