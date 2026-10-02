// Original contextual static-artifact rule; references can match.
rule ASPL_Keyboard_Hook_Log_Write_Context
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1056/001/"
        license = "ISC"
        description = "Keyboard hook, key naming and file-write capabilities; accessibility and sample code can match."
        category = "input-capture"
        confidence = "low"
        severity = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Keyboard hook, key naming and file-write capabilities; accessibility and sample code can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1056.001"
    strings:
        $artifact1 = "SetWindowsHookEx" ascii wide nocase
        $artifact2 = "WH_KEYBOARD_LL" ascii wide nocase
        $artifact3 = "GetKeyNameText" ascii wide nocase
        $artifact4 = "WriteFile" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact4 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
