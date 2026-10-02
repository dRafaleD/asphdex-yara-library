rule ASPL_PowerShell_Base64_IEX
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1027/"
        license = "ISC"
        description = "Expression execution wraps base64 text decoding"
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
        $anchor = "FromBase64String" ascii wide nocase
        $chain = /(IEX|Invoke-Expression)[ \t]+[^\r\n]{0,128}GetString[ \t]*\([^\r\n]{0,96}FromBase64String[ \t]*\([ \t]*['"][A-Za-z0-9+\/=]{8,256}['"]/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
