rule ASPL_PowerShell_Gzip_Reflection_Load
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1027/"
        license = "ISC"
        description = "Gzip stream decompression and copy precedes reflection load"
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
        $anchor = "GzipStream" ascii wide nocase
        $chain = /(System\.IO\.Compression\.)?GzipStream[^\r\n]{0,128}Decompress[^\r\n]{0,256}CopyTo[ \t]*\([^\r\n]{0,256}\[System\.Reflection\.Assembly\]::Load[ \t]*\([ \t]*\$[a-z_][a-z0-9_]{0,32}\.ToArray[ \t]*\(\)[ \t]*\)/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
