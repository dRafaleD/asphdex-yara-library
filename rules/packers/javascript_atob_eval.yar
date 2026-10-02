rule ASPL_JavaScript_Atob_Eval
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1027/"
        license = "ISC"
        description = "JavaScript eval directly consumes a base64-decoded literal"
        category = "obfuscation"
        severity = "low"
        confidence = "low"
        rule_version = "1.0.0"
        created = "2026-10-02"
        modified = "2026-10-02"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Obfuscation artifact only, not a packer signature or malware verdict. Data flow and decoded content are not validated. Quotes and legitimate generators may match."
        minimum_yara = "4.5.0"
    strings:
        $anchor = "atob" ascii wide nocase
        $chain = /eval[ \t]*\([ \t]*atob[ \t]*\([ \t]*['"][A-Za-z0-9+\/=]{8,256}['"][ \t]*\)[ \t]*\)/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
