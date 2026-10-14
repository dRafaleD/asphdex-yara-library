// Original AsphDex static-artifact review rule. ISC license.
rule ASPL_VSCode_Task_Remote_Shell
{
    meta:
        author = "AsphDex contributors"
        source = "https://socket.dev/supply-chain-attacks/polinrider"
        license = "ISC"
        description = "VS Code shell task contains a remote retrieval command in task configuration."
        category = "scripted-execution"
        severity = "high"
        confidence = "medium"
        rule_version = "1.0.0"
        created = "2026-10-07"
        modified = "2026-10-07"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Developer tasks can legitimately download dependencies or test resources. This detects textual task configuration only and does not prove automatic execution, compromise, or malicious intent. Split commands, variables, helper scripts, alternate task providers, and encoded URLs may evade it."
        minimum_yara = "4.5.0"
        attack_id = "T1059"
    strings:
        $tasks = "\"tasks\"" ascii wide nocase
        $shell = /\"type\"[ \t\r\n]*:[ \t\r\n]*\"shell\"/ ascii wide nocase
        $remote_cmd = /\"command\"[ \t\r\n]*:[ \t\r\n]*\"[^\"\r\n]{0,192}(curl|wget|powershell|pwsh)(\.exe)?[^\"\r\n]{0,256}https?:\/\// ascii wide nocase
    condition:
        filesize > 0 and filesize <= 1048576 and $tasks and $shell and $remote_cmd
}
