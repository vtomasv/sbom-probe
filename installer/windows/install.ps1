[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [string]$Deployment,
    [Parameter(Mandatory = $true, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecuta PowerShell como administrador.'
}

$homeDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SBOM Probe'
$taskName = 'SBOM Probe'
$deploymentFiles = @('config.json', 'ca.crt', 'client.token', 'client.crt', 'client.key')
$binaryFiles = @('sbom-probe.exe', 'syft.exe')
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')

function Stop-ProbeTask {
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($null -eq $task) { return }
    Disable-ScheduledTask -InputObject $task | Out-Null
    Stop-ScheduledTask -InputObject $task
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if ((Get-ScheduledTask -TaskName $taskName -TaskPath '\').State -ne 'Running') { return }
        Start-Sleep -Milliseconds 500
    }
    throw 'La tarea de la sonda todavía está en ejecución.'
}

function Remove-ProbeFiles {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $path = Join-Path $homeDir $name
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
}

if ($Uninstall) {
    Stop-ProbeTask
    if (Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false
    }
    Remove-ProbeFiles -Names ($deploymentFiles + $binaryFiles + @('install.ps1', 'run-probe.cmd'))
    Write-Host "Sonda desinstalada. La identidad y los datos pendientes siguen en $homeDir\state."
    exit 0
}

$nativeArchitecture = $env:PROCESSOR_ARCHITEW6432
if (!$nativeArchitecture) { $nativeArchitecture = $env:PROCESSOR_ARCHITECTURE }
$target = 'windows_' + $nativeArchitecture.ToLowerInvariant()
if ((Get-Content -LiteralPath (Join-Path $PSScriptRoot 'target.txt') -Raw).Trim() -ne $target) {
    throw "Usa el paquete $target."
}

$deploymentPath = (Resolve-Path -LiteralPath $Deployment).Path
foreach ($name in $deploymentFiles[0..2]) {
    if (!(Test-Path -LiteralPath (Join-Path $deploymentPath $name) -PathType Leaf)) {
        throw "Falta $name en $deploymentPath."
    }
}
$hasClientCertificate = Test-Path -LiteralPath (Join-Path $deploymentPath 'client.crt') -PathType Leaf
$hasClientKey = Test-Path -LiteralPath (Join-Path $deploymentPath 'client.key') -PathType Leaf
if ($hasClientCertificate -ne $hasClientKey) { throw 'Se requieren client.crt y client.key para mTLS.' }

$directory = [IO.Directory]::CreateDirectory($homeDir)
if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "El directorio de instalación es un punto de reanálisis: $homeDir."
}
$owner = (Get-Acl -LiteralPath $homeDir).GetOwner([Security.Principal.SecurityIdentifier])
if ($owner -notin @($identity.User, $adminSid, $systemSid)) {
    throw "El directorio de instalación tiene un propietario inesperado: $homeDir."
}
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($adminSid)
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($systemSid, $adminSid)) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
    )
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $homeDir -AclObject $acl

$staging = Join-Path $homeDir ('.install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging | Out-Null
try {
    foreach ($name in $deploymentFiles) {
        $source = Join-Path $deploymentPath $name
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $staging $name)
        }
    }
    foreach ($name in $binaryFiles) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $staging $name)
    }
    $stagedProbe = Join-Path $staging 'sbom-probe.exe'
    $stagedConfig = Join-Path $staging 'config.json'
    & $stagedProbe init -config $stagedConfig | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'La configuración de despliegue no es válida.' }

    Stop-ProbeTask
    foreach ($name in ($deploymentFiles + $binaryFiles)) {
        $source = Join-Path $staging $name
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $homeDir $name) -Force
        }
    }
    if (!$hasClientKey) { Remove-ProbeFiles -Names @('client.crt', 'client.key') }
    foreach ($name in @('install.ps1', 'run-probe.cmd')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $homeDir $name) -Force
    }
    $probe = Join-Path $homeDir 'sbom-probe.exe'
    $config = Join-Path $homeDir 'config.json'
    & $probe init -config $config
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo inicializar la identidad de la sonda.' }

    $logDirectory = Join-Path $homeDir 'logs'
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    $runner = Join-Path $homeDir 'run-probe.cmd'
    $action = New-ScheduledTaskAction -Execute (Join-Path ([Environment]::SystemDirectory) 'cmd.exe') `
        -Argument ('/d /s /c ""{0}""' -f $runner) -WorkingDirectory $homeDir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $systemSid.Value -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Trigger $trigger `
        -Principal $taskPrincipal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName -TaskPath '\'
    Write-Host "Sonda instalada. Configuración en $config."
} finally {
    Remove-Item -LiteralPath $staging -Recurse -Force
}
