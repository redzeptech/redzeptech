Write-Host "=== Suspicious Process Finder ==="

$report = @()

$processes = Get-Process -IncludeUserName -ErrorAction SilentlyContinue

foreach ($p in $processes) {
    $path = ""
    try { $path = $p.Path } catch {}

    if ($p.Name -match '^[a-z]{6,}\d{2,}$') {
        $report += [PSCustomObject]@{
            Type = "Randomized Name"
            Process = $p.Name
            PID = $p.Id
            Path = $path
            User = $p.UserName
        }
    }

    if ($p.UserName -eq "NT AUTHORITY\SYSTEM" -and $path -notmatch "Windows\\System32") {
        $report += [PSCustomObject]@{
            Type = "SYSTEM outside System32"
            Process = $p.Name
            PID = $p.Id
            Path = $path
            User = $p.UserName
        }
    }
}

$report | Format-Table -AutoSize
$report | Export-Csv suspicious_processes.csv -NoTypeInformation

Write-Host "Report saved to suspicious_processes.csv"
