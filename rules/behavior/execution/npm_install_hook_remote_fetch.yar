// Original AsphDex static-artifact review rule. ISC license.
rule ASPL_NPM_Install_Hook_Remote_Fetch
{
    meta:
        author = "AsphDex contributors"
        source = "https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/"
        license = "ISC"
        description = "npm lifecycle install hook invokes a remote retrieval utility; analyst review required."
        category = "scripted-execution"
        severity = "high"
        confidence = "medium"
        rule_version = "1.0.0"
        created = "2026-10-07"
        modified = "2026-10-07"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Install hooks legitimately download platform binaries and assets. Static text does not prove package compromise, payload execution, or malicious intent. Alternate package managers, helper scripts, variable-built URLs, aliases, and encoded commands may evade this narrow signature."
        minimum_yara = "4.5.0"
        attack_id = "T1195.002"
    strings:
        $scripts = "\"scripts\"" ascii wide
        $hook = /\"(preinstall|install|postinstall)\"[ \t\r\n]*:[ \t\r\n]*\"/ ascii wide nocase
        $tool = /(curl|wget|powershell|pwsh)(\.exe)?[ \t]/ ascii wide nocase
        $http = "http://" ascii wide nocase
        $https = "https://" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 1048576 and $scripts and
        for any i in (1 .. #hook) : (
            $tool in (@hook[i] .. @hook[i] + 1024) and
            ($http in (@hook[i] .. @hook[i] + 1024) or
             $https in (@hook[i] .. @hook[i] + 1024))
        )
}
