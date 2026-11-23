# #1764: run `x0x` commands that only parse arguments, and fail clearly when
# one ends with STATUS_STACK_OVERFLOW (0xC00000FD) instead of exit 0.
param([Parameter(Mandatory)] [string]$X0x)
$ErrorActionPreference = 'Stop'
$StackOverflow = -1073741571
$failed = 0
foreach ($arguments in @(@('--version'), @('--help'), @('autostart', '--help'))) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $X0x @arguments *> $null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $saved
    $command = "x0x $($arguments -join ' ')"
    if ($code -eq $StackOverflow) {
        Write-Host "::error::$command overflowed its stack (exit 0xC00000FD, STATUS_STACK_OVERFLOW)"
        $failed++
    } elseif ($code -ne 0) {
        Write-Host "::error::$command exited $code"
        $failed++
    } else {
        Write-Host "$command exited 0"
    }
}
if ($failed -gt 0) { exit 1 }
