# #1764 item 4: runs as a second, non-admin local user (Windows PowerShell
# 5.1). It opens a control pipe whose DACL admits Everyone, then the x0xd
# upgrade flush pipe. It never sends a request or the API token.
param(
    [Parameter(Mandatory = $true)] [string]$X0xPipe,
    [Parameter(Mandatory = $true)] [string]$ControlPipe,
    [Parameter(Mandatory = $true)] [string]$Out
)
$ErrorActionPreference = 'Stop'

function Test-PipeOpen([string]$Name) {
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', $Name, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(10000)
        return 'connected'
    } catch {
        $exception = $_.Exception
        while ($null -ne $exception) {
            if ($exception -is [System.UnauthorizedAccessException]) { return 'access-denied' }
            $exception = $exception.InnerException
        }
        return 'error: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message
    } finally {
        $client.Dispose()
    }
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$result = [ordered]@{
    identity = $identity.Name
    sid = $identity.User.Value
    is_admin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    control_pipe = Test-PipeOpen $ControlPipe
    x0x_pipe = Test-PipeOpen $X0xPipe
}
$result | ConvertTo-Json | Set-Content -Encoding ASCII -Path $Out
