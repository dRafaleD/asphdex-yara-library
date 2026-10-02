// Original contextual static-artifact rule; references can match.
rule ASPL_Comsvcs_Lsass_Dump_Context
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1003/001/"
        license = "ISC"
        description = "Comsvcs LSASS dump context; authorized diagnostics and copied instructions can match."
        category = "credential-dumping"
        confidence = "medium"
        severity = "high"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Comsvcs LSASS dump context; authorized diagnostics and copied instructions can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1003.001"
    strings:
        $artifact1 = "rundll32" ascii wide nocase
        $artifact2 = "comsvcs.dll" ascii wide nocase
        $artifact3 = "MiniDump" ascii wide nocase
        $artifact4 = "lsass" ascii wide nocase
        $artifact5 = " full" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact4 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact5 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
