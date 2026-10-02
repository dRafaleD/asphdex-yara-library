// Original AsphDex static-artifact review rule. ISC license.
rule ASPL_PowerShell_Reflection_Base64_Assembly {
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1059/001/"
        license = "ISC"
        description = "Nearby textual artifacts of powershell reflection base64 assembly; analyst review required."
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
        $a = "[Reflection.Assembly]::Load(" ascii wide nocase
        $b = "FromBase64String(" ascii wide nocase
        $c = "EntryPoint.Invoke(" ascii wide nocase
    condition:
        filesize <= 4194304 and all of them and
        for any i in (1..#a) : (
            $b in (@a[i]..@a[i] + 4096) and
            $c in (@a[i]..@a[i] + 4096)
        )
}
