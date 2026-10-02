// Original contextual static-artifact rule; references can match.
rule ASPL_Dpapi_Credential_Blob_Unprotect
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1555/004/"
        license = "ISC"
        description = "DPAPI unprotection plus credential-blob fields; legitimate credential tools and SDK reference can match."
        category = "credential-access"
        confidence = "low"
        severity = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "DPAPI unprotection plus credential-blob fields; legitimate credential tools and SDK reference can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1555.004"
    strings:
        $artifact1 = "CryptUnprotectData" ascii wide nocase
        $artifact2 = "CredentialBlob" ascii wide nocase
        $artifact3 = "CredentialBlobSize" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
