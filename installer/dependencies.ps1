# Pinned upstream package; functions can be tested without installing anything.
$OpenVpnVersion = '2.7.4-I001'
$OpenVpnMsiName = "OpenVPN-$OpenVpnVersion-amd64.msi"
$OpenVpnSha256 = '7B70D592B421C20744D704D66A9C7B0C0FFF6B23C76A90F6AB52D9D2CECFAF25'
$OpenVpnDownloadUrl = "https://swupdate.openvpn.org/community/releases/$OpenVpnMsiName"

function Assert-OpenVpnPackage([string]$Path) {
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $OpenVpnSha256) {
        throw "OpenVPN SHA-256 mismatch: $Path"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|, )CN=OpenVPN Inc\.(,|$)') {
        throw "OpenVPN Authenticode verification failed: $Path ($($signature.Status))"
    }
}

function Get-OpenVpnPackage([string]$Destination) {
    if (Test-Path -LiteralPath $Destination) {
        try {
            Assert-OpenVpnPackage $Destination
            return
        } catch {
            Write-Warning 'Cached OpenVPN package failed validation; replacing it with a verified download.'
        }
    }
    New-Item -ItemType Directory -Path (Split-Path $Destination) -Force | Out-Null
    $temporary = "$Destination.$([guid]::NewGuid().ToString('N')).download"
    try {
        Invoke-WebRequest -Uri $OpenVpnDownloadUrl -OutFile $temporary -UseBasicParsing
        Assert-OpenVpnPackage $temporary
        # Same-directory rename/replace publishes the complete verified file.
        if (Test-Path -LiteralPath $Destination) {
            [System.IO.File]::Replace($temporary, $Destination, [NullString]::Value)
        } else {
            [System.IO.File]::Move($temporary, $Destination)
        }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}
