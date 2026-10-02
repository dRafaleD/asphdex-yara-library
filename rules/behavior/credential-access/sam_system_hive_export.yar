// Original contextual static-artifact rule; references can match.
rule ASPL_Sam_System_Hive_Export
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1003/002/"
        license = "ISC"
        description = "Paired SAM and SYSTEM hive-export text; authorized backup can match."
        category = "credential-dumping"
        confidence = "medium"
        severity = "high"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Paired SAM and SYSTEM hive-export text; authorized backup can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1003.002"
    strings:
        $artifact1 = "reg save HKLM\\SAM" ascii wide nocase
        $artifact2 = "reg save HKLM\\SYSTEM" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
