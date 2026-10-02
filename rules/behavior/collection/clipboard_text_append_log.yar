// Original contextual static-artifact rule; references can match.
rule ASPL_Clipboard_Text_Append_Log
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1115/"
        license = "ISC"
        description = "Clipboard read and file-value append artifacts; productivity scripts can match."
        category = "input-capture"
        confidence = "low"
        severity = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Clipboard read and file-value append artifacts; productivity scripts can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1115"
    strings:
        $artifact1 = "Get-Clipboard" ascii wide nocase
        $artifact2 = "Add-Content" ascii wide nocase
        $artifact3 = " -Value " ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
