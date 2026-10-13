# KeePassAccess client for PowerShell (Windows PowerShell 5.1+ and PowerShell 7). Reads entries tagged
# ExternalAccess from a running, unlocked KeePass with the KeePassAccess plugin; protocol: see README.md.
# https://github.com/jelinj8/Java-KeePassAccess - LGPL-2.1
#
#   . .\KeePassAccess.ps1
#   $password = Get-KeePassField app-db-user                 # by name tag, Password field
#   $dbHost   = Get-KeePassField app-db-user HOST            # any field
#   $entry    = Get-KeePassEntry 3F2504E04F8911D39A0C0305E82C3301
#
# Errors are thrown as exceptions ("KeePassAccess: LOCKED ...", "KeePassAccess: NOT_FOUND ...").
# The pipe name can be overridden with the environment variable KEEPASS_ACCESS_PIPE.
# Keep this file ASCII: Windows PowerShell reads scripts without BOM in the ANSI codepage.

# Sends one request line; returns the response lines without the terminating empty line.
function Invoke-KeePassAccess([Parameter(Mandatory)][string]$Request) {
    $name = $env:KEEPASS_ACCESS_PIPE
    if (-not $name) { $name = "KeePassAccess-$env:USERNAME" }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        try { $pipe.Connect(3000) } catch { throw "KeePassAccess: KeePass with the KeePassAccess plugin is not running (pipe $name)" }
        $bytes = $utf8.GetBytes($Request + "`n")
        $pipe.Write($bytes, 0, $bytes.Length)
        $pipe.Flush()
        $text = (New-Object System.IO.StreamReader($pipe, $utf8)).ReadToEnd()
    } finally { $pipe.Dispose() }
    if (-not $text.EndsWith("`n`n")) { throw "KeePassAccess: incomplete response from KeePass on pipe $name" }
    $lines = $text.Substring(0, $text.Length - 2).Split("`n")
    if ($lines[0] -like 'ERR *') { throw "KeePassAccess: $($lines[0].Substring(4))" }
    $lines
}

function ConvertFrom-KeePassBase64([string]$Value) {
    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value))
}

# All string fields of an entry as an ordered hashtable (field name -> value). $Ref is the entry UUID
# (32 hex digits; dashes, braces and spaces are ignored) or a name tag of the entry.
function Get-KeePassEntry([Parameter(Mandatory)][string]$Ref) {
    $hex = $Ref -replace '[-{}\s]', ''
    $request = if ($hex -match '^[0-9a-fA-F]{32}$') { "GET $hex" } else { "FIND $Ref" }
    $entry = New-Object System.Collections.Specialized.OrderedDictionary([StringComparer]::Ordinal)
    foreach ($line in (Invoke-KeePassAccess $request | Select-Object -Skip 1)) {
        $kv = $line.Split("`t")
        $entry[(ConvertFrom-KeePassBase64 $kv[0])] = ConvertFrom-KeePassBase64 $kv[1]
    }
    $entry
}

# One field of an entry (default Password): Title, UserName, Password, URL, Notes or a custom field. The name
# is matched exactly first, then case-insensitively; throws if the entry has no such field.
function Get-KeePassField([Parameter(Mandatory)][string]$Ref, [string]$Field = 'Password') {
    $entry = Get-KeePassEntry $Ref
    if ($entry.Contains($Field)) { return $entry[$Field] }
    foreach ($key in $entry.Keys) {
        if ($key -ieq $Field) { return $entry[$key] }
    }
    throw "KeePassAccess: entry $Ref has no field '$Field'"
}
