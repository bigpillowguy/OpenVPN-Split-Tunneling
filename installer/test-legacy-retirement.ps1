# Verify the installer's Win32 image-lock/removal contract on owned temporary
# files. SEC_IMAGE_NO_EXECUTE maps a copied system image without running code.
$ErrorActionPreference = 'Stop'
$directory = Join-Path ([IO.Path]::GetTempPath()) "vpn-retirement-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $directory | Out-Null
$image = Join-Path $directory 'retired-image.bin'
try {
    Copy-Item -LiteralPath (Join-Path ([Environment]::SystemDirectory) 'version.dll') -Destination $image
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class RetirementProbe {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileMappingW(SafeFileHandle file, IntPtr security, uint protect, uint high, uint low, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr MapViewOfFile(SafeFileHandle mapping, uint access, uint high, uint low, UIntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool UnmapViewOfFile(IntPtr view);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool DeleteFileW(string path);
    static SafeFileHandle Guard(string path) {
        // Keep these arguments in sync with OpenLegacyFileForRemoval in .iss.
        return CreateFileW(path, 0xC0000000, 4, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
    }
    static void Require(bool condition, string message) {
        if (!condition) throw new InvalidOperationException(message + " (" + Marshal.GetLastWin32Error() + ")");
    }
    public static void Run(string path) {
        SafeFileHandle mapping;
        using (var file = CreateFileW(path, 0x80000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
            Require(!file.IsInvalid, "Open owned image");
            mapping = CreateFileMappingW(file, IntPtr.Zero, 0x11000002, 0, 0, null); // SEC_IMAGE_NO_EXECUTE | PAGE_READONLY
            Require(!mapping.IsInvalid, "Create nonexecuting owned image section");
        }
        using (mapping) {
            IntPtr view = MapViewOfFile(mapping, 4, 0, 0, UIntPtr.Zero);
            Require(view != IntPtr.Zero, "Map owned image without executing it");
            try {
                using (var blocked = Guard(path)) {
                    int error = Marshal.GetLastWin32Error();
                    Require(blocked.IsInvalid && (error == 5 || error == 32 || error == 33), "Mapped image must refuse removal guard");
                }
                Require(File.Exists(path), "Refusal preserves mapped image");
            } finally { Require(UnmapViewOfFile(view), "Unmap owned image"); }
        }
        using (var guard = Guard(path)) {
            Require(!guard.IsInvalid, "Unmapped image accepts removal guard");
            using (var racedReader = CreateFileW(path, 0x80000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
                Require(racedReader.IsInvalid && Marshal.GetLastWin32Error() == 32, "Guard prevents a new reader before deletion");
            }
            Require(DeleteFileW(path), "Exact owned image deletes while guard remains held");
        }
        Require(!File.Exists(path), "Owned image removed after guard closes");
        using (var missing = Guard(path)) {
            Require(missing.IsInvalid && Marshal.GetLastWin32Error() == 2, "Fresh install has no retired image");
        }
    }
}
'@
    [RetirementProbe]::Run($image)
    Write-Host 'PASS: mapped-image refusal, guarded deletion, reader-race exclusion, and absent-file handling.'
} finally {
    # Only exact files created by this test and its now-empty directory.
    if (Test-Path -LiteralPath $image) { Remove-Item -LiteralPath $image }
    Remove-Item -LiteralPath $directory
}
