# ============================================================
#  huntReady-sysmon · Assistant d'enrichissement Sysmon
#  Famille Outils Compagnon — DOUKAKAS Yeni
#  Compagnon de huntReady-compagnon (maillon « Enrichissement »)
#
#  Cet outil TÉLÉCHARGE et INSTALLE Sysmon (Microsoft Sysinternals)
#  pour enrichir la télémétrie de détection du poste.
#  Téléchargement depuis la source officielle Microsoft uniquement,
#  signature vérifiée, et rien n'est installé sans confirmation.
# ============================================================

# ----- Auto-élévation administrateur -----
$identite  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identite)
$estAdmin  = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $estAdmin) {
    Write-Host "Cet outil a besoin des droits administrateur. Élévation en cours..." -ForegroundColor Yellow
    $hote = (Get-Process -Id $PID).Path
    Start-Process -FilePath $hote -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# ----- Encodage console en UTF-8 -----
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ----- Bandeau d'accueil -----
$largeur = 54
$ligne   = "═" * $largeur
$titre   = "   huntReady-sysmon · Enrichissement Sysmon"

Write-Host ""
Write-Host "  ╔$ligne╗" -ForegroundColor Magenta
Write-Host ("  ║" + $titre.PadRight($largeur) + "║") -ForegroundColor Magenta
Write-Host "  ╚$ligne╝" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Cet outil installe Sysmon (Microsoft Sysinternals) pour" -ForegroundColor Gray
Write-Host "  enrichir la télémétrie de détection de ce poste." -ForegroundColor Gray
Write-Host ""
Write-Host "  Contrat de confiance :" -ForegroundColor White
Write-Host "   • Téléchargement depuis la source officielle Microsoft." -ForegroundColor Gray
Write-Host "   • Signature numérique vérifiée avant toute exécution." -ForegroundColor Gray
Write-Host "   • Rien n'est installé sans ta confirmation explicite." -ForegroundColor Gray
Write-Host ""
Write-Host "  Poste : $env:COMPUTERNAME" -ForegroundColor Magenta
Write-Host ""

# ===== ÉTAPES (ajoutées progressivement) =====
# ===== DÉTECTION DE SYSMON =====
function Get-EtatSysmon {
    $service = Get-Service -Name "Sysmon","Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $service) {
        return @{ Installe = $false; EnCours = $false; Service = $null; Version = $null }
    }
    $version = $null
    $svcWmi = Get-CimInstance Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
    if ($svcWmi -and $svcWmi.PathName) {
        $chemin = $svcWmi.PathName.Trim('"')
        if (Test-Path $chemin) {
            $version = (Get-Item $chemin).VersionInfo.ProductVersion
        }
    }
    return @{
        Installe = $true
        EnCours  = ($service.Status -eq 'Running')
        Service  = $service.Name
        Version  = $version
    }
}


# ===== OUTILS =====
function Confirm-Action {
    param([string]$Question)
    while ($true) {
        $r = (Read-Host "$Question (O/N)").Trim().ToUpper()
        if ($r -in 'O','OUI') { return $true }
        if ($r -in 'N','NON') { return $false }
        Write-Host "   Reponds par O (oui) ou N (non)." -ForegroundColor Yellow
    }
}

function Get-SysmonVerifie {
    $url     = "https://download.sysinternals.com/files/Sysmon.zip"
    $dossier = Join-Path $env:TEMP "huntReady-sysmon"
    $zip     = Join-Path $dossier "Sysmon.zip"

    if (Test-Path $dossier) { Remove-Item $dossier -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $dossier -Force | Out-Null

    Write-Host "   Téléchargement depuis la source officielle Microsoft..." -ForegroundColor Gray
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $dossier -Force
    } catch {
        Write-Host "   ✗ Échec du téléchargement ou de l'extraction : $($_.Exception.Message)" -ForegroundColor Red
        return @{ Ok = $false }
    }

    $nomExe = if ([Environment]::Is64BitOperatingSystem) { "Sysmon64.exe" } else { "Sysmon.exe" }
    $exe = Join-Path $dossier $nomExe
    if (-not (Test-Path $exe)) {
        Write-Host "   ✗ $nomExe introuvable après extraction." -ForegroundColor Red
        return @{ Ok = $false }
    }

    Write-Host "   Vérification de la signature numérique..." -ForegroundColor Gray
    $sig = Get-AuthenticodeSignature -FilePath $exe
    $estMicrosoft = $sig.SignerCertificate -and ($sig.SignerCertificate.Subject -match 'Microsoft Corporation')
    if ($sig.Status -ne 'Valid' -or -not $estMicrosoft) {
        Write-Host "   ✗ Signature non valide ou éditeur inattendu — on s'arrête là." -ForegroundColor Red
        Write-Host "     Statut : $($sig.Status)" -ForegroundColor Red
        return @{ Ok = $false }
    }

    $version = (Get-Item $exe).VersionInfo.ProductVersion
    Write-Host "   ✓ Signature valide (Microsoft Corporation)." -ForegroundColor Green
    Write-Host "   ✓ Sysmon $version téléchargé et prêt." -ForegroundColor Green
    return @{ Ok = $true; Exe = $exe; Dossier = $dossier; Version = $version }
}


# ===== CONFIGURATION ET INSTALLATION =====
function Get-ConfigBaseline {
    return @"
<Sysmon schemaversion="4.50">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation>false</CheckRevocation>
  <EventFiltering>
    <ProcessCreate onmatch="exclude"></ProcessCreate>
    <ProcessAccess onmatch="include">
      <TargetImage condition="image">lsass.exe</TargetImage>
    </ProcessAccess>
    <CreateRemoteThread onmatch="exclude"></CreateRemoteThread>
    <NetworkConnect onmatch="include">
      <Image condition="contains">powershell</Image>
      <Image condition="contains">cmd.exe</Image>
      <Image condition="contains">wscript</Image>
      <Image condition="contains">cscript</Image>
      <Image condition="contains">mshta</Image>
      <Image condition="contains">rundll32</Image>
    </NetworkConnect>
    <DnsQuery onmatch="include">
      <Image condition="contains">powershell</Image>
      <Image condition="contains">cmd.exe</Image>
      <Image condition="contains">mshta</Image>
      <Image condition="contains">rundll32</Image>
    </DnsQuery>
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
    </RegistryEvent>
    <FileCreateStreamHash onmatch="include">
      <TargetFilename condition="end with">.exe</TargetFilename>
    </FileCreateStreamHash>
  </EventFiltering>
</Sysmon>
"@
}

function Install-Sysmon {
    param($Exe, $Dossier)
    $config = Join-Path $Dossier "sysmon-baseline.xml"
    [System.IO.File]::WriteAllText($config, (Get-ConfigBaseline), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "   Installation de Sysmon avec la baseline intégrée..." -ForegroundColor Gray
    & $Exe -accepteula -i $config | Out-Null
    Start-Sleep -Seconds 2
    $e = Get-EtatSysmon
    if ($e.Installe -and $e.EnCours) {
        Write-Host "   ✓ Sysmon installé et en cours d'exécution (service $($e.Service))." -ForegroundColor Green
        Write-Host "   ✓ Maillon « Enrichissement » désormais en place." -ForegroundColor Green
    } else {
        Write-Host "   ✗ L'installation n'a pas abouti comme prévu." -ForegroundColor Red
    }
}


# ===== DÉROULEMENT =====
$etat = Get-EtatSysmon

Write-Host "  --- État de Sysmon ---" -ForegroundColor Magenta
if ($etat.Installe) {
    $ver = if ($etat.Version) { " version $($etat.Version)" } else { "" }
    if ($etat.EnCours) {
        Write-Host "   ✓ Sysmon est installé (service $($etat.Service)$ver) et en cours d'exécution." -ForegroundColor Green
    } else {
        Write-Host "   ! Sysmon est installé (service $($etat.Service)$ver) mais le service est arrêté." -ForegroundColor Yellow
    }
} else {
    Write-Host "   → Sysmon n'est pas installé sur ce poste." -ForegroundColor Yellow
    Write-Host "     Le maillon « Enrichissement » est donc absent." -ForegroundColor Gray
    Write-Host ""
    if (Confirm-Action "   Télécharger et vérifier Sysmon depuis Microsoft ?") {
        $sysmon = Get-SysmonVerifie
        if ($sysmon.Ok) {
            Write-Host ""
            Write-Host "   La baseline intégrée capte : processus, accès LSASS, injection," -ForegroundColor Gray
            Write-Host "   réseau et DNS des interpréteurs, persistance et flux ADS." -ForegroundColor Gray
            Write-Host ""
            if (Confirm-Action "   Installer Sysmon avec cette baseline ?") {
                Install-Sysmon -Exe $sysmon.Exe -Dossier $sysmon.Dossier
            } else {
                Write-Host "   Installation annulée." -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "   Annulé. Aucun téléchargement." -ForegroundColor Yellow
    }
}

Write-Host ""
Read-Host "  Appuie sur Entrée pour fermer"