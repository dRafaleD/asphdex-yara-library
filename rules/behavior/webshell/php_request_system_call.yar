// Original AsphDex static-artifact review rule. ISC license.
rule ASPL_PHP_Request_System_Call {
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1505/003/"
        license = "ISC"
        description = "Nearby textual artifacts of php request system call; analyst review required."
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
        $a = "<?php" ascii wide nocase
        $b = "system($_REQUEST[" ascii wide nocase
    condition:
        filesize <= 4194304 and all of them and
        for any i in (1..#a) : (
            $b in (@a[i]..@a[i] + 4096)
        )
}
