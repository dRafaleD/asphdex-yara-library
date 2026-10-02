rule ASPL_AuditPolicy_Success_Failure_Disable
{
    meta:
        author = "AsphDex contributors"
        source = "https://attack.mitre.org/techniques/T1562/002/"
        license = "ISC"
        description = "Audit policy disables success and failure auditing"
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
        $anchor = "auditpol" ascii wide nocase
        $chain = /auditpol(\.exe)?[ \t]+\/set[^\r\n]{0,192}\/success:disable[^\r\n]{0,96}\/failure:disable/ ascii wide nocase
    condition:
        filesize < 20MB and $anchor and $chain
}
