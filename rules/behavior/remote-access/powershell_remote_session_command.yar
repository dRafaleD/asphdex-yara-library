// Original contextual static-artifact rule; references can match.
rule ASPL_Powershell_Remote_Session_Command
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1021/006/"
        license = "ISC"
        description = "Remote session with a session-bound command block; authorized administration can match."
        category = "remote-command"
        confidence = "low"
        severity = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Remote session with a session-bound command block; authorized administration can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1021.006"
    strings:
        $artifact1 = "New-PSSession" ascii wide nocase
        $artifact2 = "-ComputerName" ascii wide nocase
        $artifact3 = "Invoke-Command" ascii wide nocase
        $artifact4 = "-Session" ascii wide nocase
        $artifact5 = "-ScriptBlock" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact4 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact5 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
