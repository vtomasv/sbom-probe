$env:PSModulePath = [IO.Path]::Combine($PSHOME,'Modules')
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
try {
    $homeDir = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Monitor SBOM'
    $registro = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MonitorSBOMProbe'
    if ($env:SBOM_SETUP_ACTION -eq 'uninstall') {
        $task = Get-ScheduledTask -TaskName 'SBOM Probe' -TaskPath '\' -ErrorAction SilentlyContinue
        if ($task) { Stop-ScheduledTask -InputObject $task; Unregister-ScheduledTask -InputObject $task -Confirm:$false }
        if (Test-Path $registro) { Remove-Item -LiteralPath $registro -Recurse -Force }
        if (Test-Path -LiteralPath $homeDir) {
            Get-ChildItem -LiteralPath $homeDir -Filter 'sonda-*.exe' | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        Write-Output 'Sonda desinstalada. Se conserva la identidad para una futura instalación.'
        exit 0
    }
    $profileFile = $env:SBOM_SETUP_PROFILE
    if (!(Test-Path -LiteralPath $profileFile -PathType Leaf)) {
        $dialog = New-Object Windows.Forms.OpenFileDialog
        $dialog.Title = 'Seleccione el perfil privado de este equipo'
        $dialog.Filter = 'Perfil de sonda (*.sbom)|*.sbom'
        if ($dialog.ShowDialog() -ne 'OK') { exit 2 }
        $profileFile = $dialog.FileName
    }
    $admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    # Program Files is administrator-owned. All credentials inherit the protected ACL.
    $homeDir = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Monitor SBOM'
    $dir = [IO.Directory]::CreateDirectory($homeDir)
    if ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Ruta de instalación no válida.' }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($admin)
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($system,$admin)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    $dir.SetAccessControl($acl)
    $config = Join-Path $homeDir 'config.json'
    $legacy = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SBOM Probe\config.json'
    if (!(Test-Path -LiteralPath $config) -and (Test-Path -LiteralPath $legacy)) { $config = $legacy }
    & $env:SBOM_SETUP_SOURCE enroll -profile $profileFile -config $config
    if ($LASTEXITCODE -ne 0) { throw 'El perfil es inválido. Revise el cliente y los certificados.' }
    # A new path lets the previous worker finish until the new executable is in place.
    $next = Join-Path $homeDir ('sonda-' + [guid]::NewGuid().ToString('N') + '.exe')
    Copy-Item -LiteralPath $env:SBOM_SETUP_SOURCE -Destination $next
    $action = New-ScheduledTaskAction -Execute $next -Argument ('run -watch -config "{0}"' -f $config) -WorkingDirectory $homeDir
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $name = 'SBOM Probe'
    $old = Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
    if ($old -and $old.State -eq 'Running') {
        Stop-ScheduledTask -InputObject $old
        for ($i=0; $i -lt 30 -and (Get-ScheduledTask -TaskName $name).State -eq 'Running'; $i++){Start-Sleep -Milliseconds 500}
        if ((Get-ScheduledTask -TaskName $name).State -eq 'Running') { throw 'La sonda anterior sigue activa.' }
    }
    Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $name
    New-Item -Path $registro -Force | Out-Null
    Set-ItemProperty $registro DisplayName 'Sonda Monitor SBOM'
    Set-ItemProperty $registro DisplayVersion ((& $next version) | Out-String).Trim()
    Set-ItemProperty $registro UninstallString ('"{0}" uninstall' -f $next)
    Get-ChildItem -LiteralPath $homeDir -Filter 'sonda-*.exe' | Where-Object FullName -ne $next | Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Output 'Sonda instalada. El primer inventario se envía en segundo plano.'
    if ([Environment]::UserInteractive -and $env:SBOM_SETUP_QUIET -ne '1') { [void][Windows.Forms.MessageBox]::Show('Sonda instalada. El primer inventario se envía en segundo plano.','Monitor SBOM') }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    if ([Environment]::UserInteractive -and $env:SBOM_SETUP_QUIET -ne '1') { [void][Windows.Forms.MessageBox]::Show($_.Exception.Message,'Error de instalación') }
    exit 1
}
