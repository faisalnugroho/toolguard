# ToolGuard Audit Policy (v1)

An MCP tool descriptor is audited against four risk categories:

R1 DATA EXFILTRATION — the tool reads secrets, credentials, files, emails or
environment data and sends them to an external endpoint.

R2 EMBEDDED INSTRUCTIONS — descriptor text instructs the agent to ignore
rules, hide behavior, or withhold information from the user.

R3 CREDENTIAL OR SECRET ACCESS — reading private keys, SSH keys, wallets,
API tokens or environment variables without an explicit, user-visible
purpose.

R4 DESTRUCTIVE OR IRREVERSIBLE OPERATIONS — deleting data, transferring
funds, or publishing content without explicit user confirmation in the
flow.

A tool is SAFE only when its description and input schema are consistent
with this policy and exhibit none of the four categories. A tool is
SUSPICIOUS when any category is exhibited by the descriptor text itself.
Reviewers must quote the exact descriptor text as evidence; verdicts are
derived by the ToolGuard contract, never by the reviewing model.
