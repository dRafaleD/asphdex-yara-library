rule ASPL_Service_Remote_BinPath
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1543/003/"
        license = "ISC"
        description = "Service creation assigns an executable on a remote UNC path"
        category = "persistence"
        severity = "medium"
        confidence = "medium"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Bounded same-line command artifact only. Comments, quoted examples and legitimate administration may match. Execution and malicious intent are not proven."
        minimum_yara = "4.5.0"
    strings:
        $anchor = "binPath" ascii wide nocase
        $chain = /sc(\.exe)?[ \t]+create[ \t]+[a-z0-9_.-]{1,64}[ \t]+binPath[ \t]*=[ \t]*"?\\\\[a-z0-9.-]{1,128}\\[^\r\n"]{1,192}\.exe/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
