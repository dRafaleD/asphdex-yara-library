rule ASPL_AMSI_Reflection_InitFlag_Set
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1562/001/"
        license = "ISC"
        description = "Reflection obtains the AMSI init flag then sets it true"
        category = "defense-evasion"
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
        $anchor = "AmsiUtils" ascii wide nocase
        $chain = /System\.Management\.Automation\.AmsiUtils[^\r\n]{0,128}GetField[ \t]*\([ \t]*['"]amsiInitFailed['"][^\r\n]{0,192}SetValue[ \t]*\([ \t]*\$null[ \t]*,[ \t]*\$true[ \t]*\)/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
