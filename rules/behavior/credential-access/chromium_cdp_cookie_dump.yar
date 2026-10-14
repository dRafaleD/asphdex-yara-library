// Original AsphDex contextual static-artifact rule. ISC license.
rule ASPL_Chromium_CDP_Cookie_Dump
{
    meta:
        author = "AsphDex contributors"
        source = "https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/"
        license = "ISC"
        description = "Chromium remote-debugging launch artifacts appear near the CDP Network.getAllCookies method."
        category = "credential-access"
        severity = "high"
        confidence = "high"
        rule_version = "1.0.1"
        created = "2026-10-07"
        modified = "2026-10-14"
        status = "experimental"
        scope = "static-artifact"
        limitation = "Browser automation, QA, debugging and security tools may legitimately use Chrome DevTools Protocol and cookie APIs. Static text does not prove cookie theft or malicious intent. Alternate CDP clients, renamed browsers, fragmented strings and other cookie methods may evade it."
        minimum_yara = "4.5.0"
        attack_id = "T1539"
    strings:
        $debug = "--remote-debugging-port" ascii wide nocase
        $cookies = "Network.getAllCookies" ascii wide
        $ws = "webSocketDebuggerUrl" ascii wide
        $chrome = "chrome.exe" ascii wide nocase
        $edge = "msedge.exe" ascii wide nocase
        $brave = "brave.exe" ascii wide nocase
    condition:
        filesize > 0 and filesize <= 2097152 and
        for any i in (1 .. #debug) : (
            $cookies in (@debug[i] .. @debug[i] + 8192) and
            $ws in (@debug[i] .. @debug[i] + 8192) and
            // The executable normally precedes its command-line switch.
            // Keep browser context within 8192 bytes in either direction.
            (for any j in (1 .. #chrome) : (
                @chrome[j] <= @debug[i] + 8192 and @chrome[j] + 8192 >= @debug[i]
             ) or for any j in (1 .. #edge) : (
                @edge[j] <= @debug[i] + 8192 and @edge[j] + 8192 >= @debug[i]
             ) or for any j in (1 .. #brave) : (
                @brave[j] <= @debug[i] + 8192 and @brave[j] + 8192 >= @debug[i]
             ))
        )
}
