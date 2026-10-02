# Category contract

The initial library groups static artifacts by behavior. File placement and
metadata category are related but not interchangeable: an execution folder may
contain `lolbin`, `scripted-execution`, or `macro-execution` metadata to preserve
AsphDex's existing scoring groups.

| Directory | Required context and procedure |
| --- | --- |
| execution | Script/command engine plus a specific load/execute expression; exclude isolated tool names |
| webshell | Request-controlled input and a command/evaluation construct; document lack of data-flow proof |
| exploit-artifacts | Specific file/document execution structure; do not assert vulnerability exploitation |
| credential-access | Target credential store and retrieval/decryption/staging operation; test legitimate export |
| collection | Target data and staging/transfer context; do not infer actual exfiltration |
| remote-access | Command/redirection/tunnel configuration combination; test ordinary networking |
| persistence | Creation/configuration operation and its startup/service/task target |
| defense-evasion | Specific defense/logging configuration change; distinguish administrative use |
| impact | Destructive/recovery-inhibition command syntax or encryption artifacts; no bare cryptography APIs |
| packers | Compound script decode/execute or obfuscation artifacts; no packer identity from entropy alone |
| families | Reserved: only distinct independently reviewed family features, not a generic behavior label |

Each procedure is: describe the artifact, identify a source, constrain syntax
and offsets, write positive/near-miss/benign/quotation fixtures, compile with both
engines, review overlap and scan cost, publish with status and limitations.
