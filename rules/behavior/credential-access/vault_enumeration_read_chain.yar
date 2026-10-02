// Original contextual static-artifact rule; references can match.
rule ASPL_Vault_Enumeration_Read_Chain
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1555/004/"
        license = "ISC"
        description = "Vault enumeration with retrieval capabilities; SDK references and credential management can match."
        category = "credential-access"
        confidence = "low"
        severity = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Vault enumeration with retrieval capabilities; SDK references and credential management can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1555.004"
    strings:
        $artifact1 = "VaultEnumerateVaults" ascii wide nocase
        $artifact2 = "VaultEnumerateItems" ascii wide nocase
        $artifact3 = "VaultGetItem" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
