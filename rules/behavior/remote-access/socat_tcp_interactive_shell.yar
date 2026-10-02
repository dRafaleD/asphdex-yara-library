// Original contextual static-artifact rule; references can match.
rule ASPL_Socat_Tcp_Interactive_Shell
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1059/004/"
        license = "ISC"
        description = "TCP bridge to a PTY shell artifact; authorized labs and recovery tools can match."
        category = "remote-command"
        confidence = "medium"
        severity = "high"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "TCP bridge to a PTY shell artifact; authorized labs and recovery tools can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1059.004"
    strings:
        $artifact1 = "socat " ascii wide nocase
        $artifact2 = "TCP:" ascii wide nocase
        $artifact3 = "EXEC:" ascii wide nocase
        $artifact4 = "/bin/sh" ascii wide nocase
        $artifact5 = ",pty" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact4 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact5 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
