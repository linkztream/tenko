# The installer's parameters the scripted install needs (an installer that takes them is
# not on this branch): the fake domain's payload, never run. Its parameter block is the
# contract the takeover script checks.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'the parameter block is the contract; nothing runs')]
[CmdletBinding()]
param(
    [string]$Url,
    [string]$MirrorId,
    [string]$Fingerprint,
    [string]$Account,
    [pscredential]$Credential,
    [securestring]$Token,
    [string]$TaskName,
    [string]$DataDir,
    [string]$ComputerName,
    [switch]$SkipDryRun,
    [switch]$Remove
)

throw 'a contract fixture; it is never run'
