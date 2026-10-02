rule ASPL_Registry_Run_Interpreter
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1547/001/"
        license = "ISC"
        description = "Registry Run value assignment invokes an interpreter"
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
        $anchor = "CurrentVersion\\Run" ascii wide nocase
        $chain = /reg(\.exe)?[ \t]+add[ \t]+"?HK(CU|LM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"?[^\r\n]{0,128}\/v[ \t]+[^\r\n]{1,64}\/d[ \t]+"?(powershell|pwsh|cmd|wscript|cscript)(\.exe)?[ \t]+/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
