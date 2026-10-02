// Original contextual static-artifact rule; references can match.
rule ASPL_Netsh_Portproxy_External_Listen
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1572/"
        license = "ISC"
        description = "IPv4 port-proxy addition with any-address listener; network administration can match."
        category = "remote-access"
        confidence = "low"
        severity = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "IPv4 port-proxy addition with any-address listener; network administration can match. Static artifact only; contextual markers must follow one anchor within 4096 bytes. Exact reference documents are known positives. No execution or call-order proof. Excludes files over 2 MiB and encoded or variant spellings."
        minimum_yara = "4.5.0"
        attack_id = "T1572"
    strings:
        $artifact1 = "netsh interface portproxy add" ascii wide nocase
        $artifact2 = "v4tov4" ascii wide nocase
        $artifact3 = "listenaddress=0.0.0.0" ascii wide nocase
        $artifact4 = "connectaddress=" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #artifact1) : (
            $artifact2 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact3 in (@artifact1[i] .. @artifact1[i] + 4096) and
            $artifact4 in (@artifact1[i] .. @artifact1[i] + 4096)
        )
}
