// Original AsphDex static-artifact review rule. ISC license.
rule ASPL_PowerShell_Encoded_Hidden_Launch {
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1059/001/"
        license = "ISC"
        description = "Nearby textual artifacts of powershell encoded hidden launch; analyst review required."
        category = "scripted-execution"
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
        $a = "powershell" ascii wide nocase
        $b = "-EncodedCommand" ascii wide nocase
        $c = "-WindowStyle Hidden" ascii wide nocase
        $d = "-NoProfile" ascii wide nocase
    condition:
        filesize <= 4194304 and all of them and
        for any i in (1..#a) : (
            $b in (@a[i]..@a[i] + 4096) and
            $c in (@a[i]..@a[i] + 4096) and
            $d in (@a[i]..@a[i] + 4096)
        )
}
