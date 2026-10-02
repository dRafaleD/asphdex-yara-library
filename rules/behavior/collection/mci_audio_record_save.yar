// Original contextual static-artifact rule; references can match.
rule ASPL_Mci_Audio_Record_Save
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1123/"
        license = "ISC"
        description = "MCI recording and saving source artifacts; audio applications and SDK reference can match."
        category = "input-capture"
        confidence = "low"
        severity = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "MCI recording and saving source artifacts; audio applications and SDK reference can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1123"
    strings:
        $artifact1 = "mciSendString" ascii wide nocase
        $artifact2 = "type waveaudio" ascii wide nocase
        $artifact3 = "record " ascii wide nocase
        $artifact4 = "save " ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact4 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
