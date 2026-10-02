// Original AsphDex static-artifact review rule. ISC license.
rule ASPL_WSH_HTTP_Stream_Shell {
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1059/007/"
        license = "ISC"
        description = "Nearby textual artifacts of wsh http stream shell; analyst review required."
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
        $a = "MSXML2.XMLHTTP" ascii wide nocase
        $b = "responseBody" ascii wide nocase
        $c = "ADODB.Stream" ascii wide nocase
        $d = "SaveToFile(" ascii wide nocase
        $e = "WScript.Shell" ascii wide nocase
    condition:
        filesize <= 4194304 and all of them and
        for any i in (1..#a) : (
            $b in (@a[i]..@a[i] + 4096) and
            $c in (@a[i]..@a[i] + 4096) and
            $d in (@a[i]..@a[i] + 4096) and
            $e in (@a[i]..@a[i] + 4096)
        )
}
