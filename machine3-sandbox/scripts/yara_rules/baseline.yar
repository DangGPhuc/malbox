rule MalBox_PE_Executable_Header
{
    meta:
        description = "Detects standard Windows PE header (informational baseline rule)"
        author = "MalBox"
        severity = "info"
    condition:
        uint16(0) == 0x5A4D
}

rule MalBox_Suspicious_Injection_APIs
{
    meta:
        description = "Detects common process injection / memory manipulation API string references"
        author = "MalBox"
        severity = "medium"
    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "NtCreateThreadEx" ascii wide
        $a5 = "QueueUserAPC" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of ($a*)
}

rule MalBox_Suspicious_Persistence_Strings
{
    meta:
        description = "Detects references to common Windows autorun or service persistence strings"
        author = "MalBox"
        severity = "medium"
    strings:
        $r1 = "CurrentVersion\\Run" ascii wide nocase
        $r2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $r3 = "schtasks" ascii wide nocase
        $r4 = "CreateService" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of ($r*)
}

rule MalBox_Suspicious_Network_Download_APIs
{
    meta:
        description = "Detects common WinINet / URLMon download API references"
        author = "MalBox"
        severity = "low"
    strings:
        $n1 = "URLDownloadToFile" ascii wide
        $n2 = "InternetOpenUrl" ascii wide
        $n3 = "HttpSendRequest" ascii wide
        $n4 = "WinHttpOpen" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of ($n*)
}
