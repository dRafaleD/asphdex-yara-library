// Original AsphDex static-artifact review rule. ISC license.
rule ASPL_Cloudflared_Local_Tunnel
{
    meta:
        author = "AsphDex contributors"
        source = "https://www.cisa.gov/sites/default/files/2025-03/aa25-071a-stopransomware-medusa-ransomware.pdf"
        license = "ISC"
        description = "Cloudflared tunnel command exposes a local service through a remote tunnel."
        category = "remote-access"
        severity = "medium"
        confidence = "high"
        rule_version = "1.0.0"
        created = "2026-10-07"
        modified = "2026-10-07"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Cloudflare Tunnel is a legitimate administration and development tool. This rule identifies a local-service tunnel command only and does not prove unauthorized access, command-and-control, or malicious intent. Option reordering, config-file use, named tunnels and non-loopback targets may evade it."
        minimum_yara = "4.5.0"
        attack_id = "T1219"
    strings:
        $cmd = /cloudflared(\.exe)?[ \t]+tunnel[ \t]+--url[ \t]+(http|https|tcp):\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0):[0-9]{2,5}/ ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and $cmd
}
