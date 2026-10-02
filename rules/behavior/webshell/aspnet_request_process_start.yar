// Original AsphDex static-artifact review rule. ISC license.
rule ASPL_ASPNET_Request_Process_Start {
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1505/003/"
        license = "ISC"
        description = "Nearby textual artifacts of aspnet request process start; analyst review required."
        category = "remote-command"
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
        $a = "<%@" ascii wide nocase
        $b = "System.Diagnostics.Process" ascii wide nocase
        $c = "Request[" ascii wide nocase
        $d = "Arguments =" ascii wide nocase
        $e = "cmd.exe" ascii wide nocase
    condition:
        filesize <= 4194304 and all of them and
        for any i in (1..#a) : (
            $b in (@a[i]..@a[i] + 4096) and
            $c in (@a[i]..@a[i] + 4096) and
            $d in (@a[i]..@a[i] + 4096) and
            $e in (@a[i]..@a[i] + 4096)
        )
}
