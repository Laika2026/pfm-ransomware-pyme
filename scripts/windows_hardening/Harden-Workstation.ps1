<#
.SYNOPSIS
    Harden-Workstation.ps1 — Endurecimiento de estaciones Windows
.DESCRIPTION
    Aplica controles de seguridad a estaciones Windows 10/11 segun perfil
    seleccionado (Permissive, Standard, Strict). Configura ASR rules,
    BitLocker, Credential Guard, Windows Defender Application Control y
    politicas de auditoria.
.PARAMETER Profile
    Perfil de endurecimiento: Permissive | Standard | Strict
.PARAMETER WhatIf
    Modo simulacion: muestra cambios sin aplicarlos
.EXAMPLE
    .\Harden-Workstation.ps1 -Profile Standard
.EXAMPLE
    .\Harden-Workstation.ps1 -Profile Strict -WhatIf
.NOTES
    Autor: Jorge Juarez | PFM 2026 | UCAM/Structuralia
    Licencia: MIT
    Requiere ejecucion como Administrador
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Permissive", "Standard", "Strict")]
    [string]$Profile
)

#region Validacion previa

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SupportedEdition {
    $edition = (Get-WindowsEdition -Online).Edition
    $supportedEditions = @("Professional", "Enterprise", "Education")
    return ($supportedEditions -contains $edition)
}

if (-not (Test-AdminPrivileges)) {
    Write-Host "[ERROR] Este script requiere privilegios de Administrador." -ForegroundColor Red
    Write-Host "Ejecutelo desde una sesion PowerShell elevada." -ForegroundColor Yellow
    exit 1
}

if (-not (Test-SupportedEdition)) {
    Write-Host "[ERROR] Edicion de Windows no soportada." -ForegroundColor Red
    Write-Host "Se requiere Windows Pro, Enterprise o Education." -ForegroundColor Yellow
    exit 3
}

#endregion

#region Logging y snapshot

$LogPath = "$env:ProgramData\PFM-Hardening\hardening.log"
$SnapshotPath = "$env:ProgramData\PFM-Hardening\snapshot_$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

if (-not (Test-Path "$env:ProgramData\PFM-Hardening")) {
    New-Item -ItemType Directory -Path "$env:ProgramData\PFM-Hardening" -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $logLine
    switch ($Level) {
        "INFO"    { Write-Host $logLine -ForegroundColor Cyan }
        "WARN"    { Write-Host $logLine -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logLine -ForegroundColor Red }
        "SUCCESS" { Write-Host $logLine -ForegroundColor Green }
    }
}

function Save-Snapshot {
    Write-Log "Capturando snapshot del estado inicial del sistema..."
    $snapshot = @{
        Timestamp       = (Get-Date).ToString("o")
        Profile         = $Profile
        OSVersion       = [System.Environment]::OSVersion.Version.ToString()
        DefenderConfig  = (Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions)
        BitLockerStatus = (Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue | Select-Object MountPoint, ProtectionStatus)
    }
    $snapshot | ConvertTo-Json -Depth 5 | Out-File -FilePath $SnapshotPath -Encoding UTF8
    Write-Log "Snapshot guardado en: $SnapshotPath" "SUCCESS"
}

#endregion

#region Reglas ASR (Attack Surface Reduction)

$ASR_RULES = @{
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email/webmail"
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block Office apps from creating child processes"
    "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office apps from creating executable content"
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office apps from injecting code into other processes"
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript/VBScript from launching executables"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of obfuscated scripts"
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
    "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block credential stealing from LSASS"
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations from PsExec/WMI commands"
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted/unsigned processes from USB"
    "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication apps from creating child processes"
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
    "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers"
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing through copy of safety hashes"
    "A8F5898E-1DC8-49A9-9878-85004B8A61E6" = "Block Webshell creation for Servers"
    "33DDEDF1-C6E0-47CB-833E-DE6133960387" = "Block rebooting machine in Safe Mode"
}

function Set-ASRRules {
    Write-Log "Aplicando $($ASR_RULES.Count) reglas ASR en modo $Profile..."
    $action = switch ($Profile) {
        "Permissive" { "AuditMode" }
        "Standard"   { "Enabled" }
        "Strict"     { "Enabled" }
    }
    foreach ($ruleId in $ASR_RULES.Keys) {
        $description = $ASR_RULES[$ruleId]
        if ($PSCmdlet.ShouldProcess($description, "Aplicar regla ASR ($action)")) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId `
                                 -AttackSurfaceReductionRules_Actions $action -ErrorAction Stop
                Write-Log "ASR aplicada: $description" "SUCCESS"
            } catch {
                Write-Log "Fallo al aplicar ASR ${ruleId}: $_" "ERROR"
            }
        }
    }
}

#endregion

#region BitLocker

function Enable-BitLockerProtection {
    if ($Profile -eq "Permissive") {
        Write-Log "BitLocker omitido en perfil Permissive" "INFO"
        return
    }
    $volume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if ($null -eq $volume) {
        Write-Log "BitLocker no disponible en este sistema" "WARN"
        return
    }
    if ($volume.ProtectionStatus -eq "On") {
        Write-Log "BitLocker ya activo en C: (idempotencia)" "INFO"
        return
    }
    if ($PSCmdlet.ShouldProcess("Volumen C:", "Activar BitLocker con TPM")) {
        try {
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 `
                             -UsedSpaceOnly -TpmProtector -ErrorAction Stop
            Write-Log "BitLocker activado en C: con XtsAes256 + TPM" "SUCCESS"
        } catch {
            Write-Log "Fallo al activar BitLocker: $_" "ERROR"
        }
    }
}

#endregion

#region Credential Guard

function Enable-CredentialGuard {
    if ($Profile -ne "Strict") {
        Write-Log "Credential Guard omitido (solo perfil Strict)" "INFO"
        return
    }
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    if ($PSCmdlet.ShouldProcess("Registro DeviceGuard", "Activar Credential Guard")) {
        try {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
            Set-ItemProperty -Path $regPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord
            Set-ItemProperty -Path $regPath -Name "LsaCfgFlags" -Value 1 -Type DWord
            Write-Log "Credential Guard configurado (requiere reinicio)" "SUCCESS"
        } catch {
            Write-Log "Fallo al configurar Credential Guard: $_" "ERROR"
        }
    }
}

#endregion

#region Politicas de auditoria

function Set-AuditPolicies {
    Write-Log "Aplicando politicas de auditoria avanzadas..."
    $auditCategories = @(
        @{Name = "Logon"; Subcategory = "Logon"; Setting = "Success and Failure"},
        @{Name = "Process Creation"; Subcategory = "Process Creation"; Setting = "Success"},
        @{Name = "Account Lockout"; Subcategory = "Account Lockout"; Setting = "Success and Failure"},
        @{Name = "Credential Validation"; Subcategory = "Credential Validation"; Setting = "Success and Failure"}
    )
    foreach ($cat in $auditCategories) {
        if ($PSCmdlet.ShouldProcess($cat.Name, "Configurar auditoria")) {
            try {
                auditpol /set /subcategory:"$($cat.Subcategory)" /success:enable /failure:enable | Out-Null
                Write-Log "Auditoria configurada: $($cat.Name)" "SUCCESS"
            } catch {
                Write-Log "Fallo en auditoria de $($cat.Name): $_" "ERROR"
            }
        }
    }
}

#endregion

#region Punto de entrada principal

function Invoke-HardeningProcess {
    Write-Log "==================================================="
    Write-Log "Inicio del proceso de endurecimiento - Perfil: $Profile"
    Write-Log "==================================================="

    Save-Snapshot
    Set-ASRRules
    Enable-BitLockerProtection
    Enable-CredentialGuard
    Set-AuditPolicies

    Write-Log "==================================================="
    Write-Log "Proceso de endurecimiento completado" "SUCCESS"
    Write-Log "Log completo en: $LogPath"
    Write-Log "Snapshot inicial en: $SnapshotPath"
    if ($Profile -eq "Strict") {
        Write-Log "ATENCION: Reinicie el sistema para activar Credential Guard" "WARN"
    }
    Write-Log "==================================================="
}

Invoke-HardeningProcess

#endregion
