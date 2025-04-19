rule Suspicious_Keywords
{
    meta:
        description = "Detects suspicious keywords often used in malware"
        author = "Ali J"
        version = "1.0"
    strings:
        $cmd1 = "cmd.exe"
        $ps1 = "powershell"
        $encoded = "base64"
        $susp1 = "mimikatz"
    condition:
        any of them
}
