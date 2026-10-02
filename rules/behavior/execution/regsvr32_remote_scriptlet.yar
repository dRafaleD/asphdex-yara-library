// Original AsphDex static-artifact review rule. ISC license.
rule ASPL_Regsvr32_Remote_Scriptlet {
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1218/010/"
        license = "ISC"
        description = "Nearby textual artifacts of regsvr32 remote scriptlet; analyst review required."
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
        $a = "regsvr32" ascii wide nocase
        $b = "/i:https://" ascii wide nocase
        $c = "scrobj.dll" ascii wide nocase
        $d = "/n" ascii wide nocase
    condition:
        filesize <= 4194304 and all of them and
        for any i in (1..#a) : (
            $b in (@a[i]..@a[i] + 4096) and
            $c in (@a[i]..@a[i] + 4096) and
            $d in (@a[i]..@a[i] + 4096)
        )
}
