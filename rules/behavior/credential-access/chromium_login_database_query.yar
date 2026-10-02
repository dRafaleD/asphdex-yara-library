// Original contextual static-artifact rule; references can match.
rule ASPL_Chromium_Login_Database_Query
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1555/003/"
        license = "ISC"
        description = "Exact Chromium password query spelling; maintenance, research and documentation can match."
        category = "credential-access"
        confidence = "medium"
        severity = "high"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Exact Chromium password query spelling; maintenance, research and documentation can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1555.003"
    strings:
        $artifact1 = "sqlite3" ascii wide nocase
        $artifact2 = "Login Data" ascii wide nocase
        $artifact3 = "SELECT origin_url, username_value, password_value FROM logins" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
