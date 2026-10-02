// Original AsphDex static-artifact review rule. ISC license.
rule ASPL_Mshta_Remote_HTA {
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1218/005/"
        license = "ISC"
        description = "Nearby textual artifacts of mshta remote hta; analyst review required."
        category = "lolbin"
        severity = "medium"
        confidence = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Text artifacts only. Comments, documentation, and authorized tools may match. Byte proximity does not prove execution, data flow, exploit success, or malware identity. Literal spacing, obfuscation, aliases, and other encodings may evade this narrow signature."
        minimum_yara = "4.5.0"
    strings:
        $a = "mshta " ascii wide nocase
        $b = "https://" ascii wide nocase
        $c = ".hta" ascii wide nocase
    condition:
        filesize <= 4194304 and all of them and
        for any i in (1..#a) : (
            $b in (@a[i]..@a[i] + 4096) and
            $c in (@a[i]..@a[i] + 4096)
        )
}
