rule ASPL_ScheduledTask_Interpreter_Action
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1053/005/"
        license = "ISC"
        description = "Task creation combines an interpreter action and recurring or startup trigger"
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
        $anchor = "schtasks" ascii wide nocase
        $chain = /schtasks(\.exe)?[ \t]+\/create[^\r\n]{0,192}\/tr[ \t]+"?(powershell|pwsh|wscript|cscript|cmd)(\.exe)?[ \t]+[^\r\n]{1,192}\/sc[ \t]+(onlogon|onstart|minute|hourly|daily)/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
