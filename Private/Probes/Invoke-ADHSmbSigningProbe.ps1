function Invoke-ADHSmbSigningProbe {
    <#
    .SYNOPSIS
        Sends an SMB2 NEGOTIATE to a host on TCP/445 and reports whether the
        server requires SMB signing.
    .DESCRIPTION
        Hand-built SMB2 NEGOTIATE following [MS-SMB2] 2.2.3 / 2.2.4. We do
        not authenticate - the NEGOTIATE response is unauthenticated and
        exposes the server's SecurityMode flags directly:

          SMB2_NEGOTIATE_SIGNING_ENABLED   (0x0001) : server supports signing
          SMB2_NEGOTIATE_SIGNING_REQUIRED  (0x0002) : server requires signing

        Hardened state: SigningRequired = $true. If the server returns only
        SigningEnabled (no Required bit), an attacker can relay SMB without
        forging signatures.

        Works against any host with port 445 open; no credentials needed.
        Modern Windows requires signing by default starting in Windows 11
        24H2 / Server 2025; older OSes need the GPO check (ADH-003).
    .PARAMETER ComputerName
        Target host. Hostname or IP.
    .PARAMETER Port
        TCP port. Default 445.
    .PARAMETER TimeoutSeconds
        Both connect + read/write timeout. Default 5.
    .OUTPUTS
        PSCustomObject with: Host, Port, SigningEnabled, SigningRequired,
        DialectRevision, ServerGuid, Method, Error, DurationMs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$Port = 445,
        [int]$TimeoutSeconds = 5
    )

    $result = [PSCustomObject]@{
        Host             = $ComputerName
        Port             = $Port
        Method           = 'SMB2 NEGOTIATE (unauthenticated)'
        SigningEnabled   = $null
        SigningRequired  = $null
        DialectRevision  = $null
        ServerGuid       = $null
        Error            = $null
        DurationMs       = 0
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = $null
    $stream = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            try { $client.Close() } catch {}
            throw "Connect timed out after $TimeoutSeconds seconds"
        }
        $client.EndConnect($iar)

        $stream = $client.GetStream()
        $stream.ReadTimeout  = $TimeoutSeconds * 1000
        $stream.WriteTimeout = $TimeoutSeconds * 1000

        # --- Build SMB2 NEGOTIATE request ---
        $ms = New-Object System.IO.MemoryStream
        $bw = New-Object System.IO.BinaryWriter($ms)

        # SMB2 Sync Header (64 bytes)
        $bw.Write([byte[]]@(0xFE, 0x53, 0x4D, 0x42))   # ProtocolId "\xFESMB"
        $bw.Write([UInt16]64)                          # StructureSize
        $bw.Write([UInt16]0)                           # CreditCharge
        $bw.Write([UInt32]0)                           # Status (reserved on request)
        $bw.Write([UInt16]0x0000)                      # Command = NEGOTIATE
        $bw.Write([UInt16]1)                           # CreditRequest
        $bw.Write([UInt32]0)                           # Flags
        $bw.Write([UInt32]0)                           # NextCommand
        $bw.Write([UInt64]0)                           # MessageId
        $bw.Write([UInt32]0)                           # Reserved
        $bw.Write([UInt32]0)                           # TreeId
        $bw.Write([UInt64]0)                           # SessionId
        $bw.Write((New-Object byte[] 16))              # Signature

        # SMB2 NEGOTIATE Request body
        $bw.Write([UInt16]36)                          # StructureSize
        $bw.Write([UInt16]1)                           # DialectCount
        $bw.Write([UInt16]0x0001)                      # SecurityMode = SIGNING_ENABLED
        $bw.Write([UInt16]0)                           # Reserved
        $bw.Write([UInt32]0)                           # Capabilities
        $bw.Write([Guid]::NewGuid().ToByteArray())     # ClientGuid (16)
        $bw.Write([UInt64]0)                           # ClientStartTime
        $bw.Write([UInt16]0x0202)                      # Dialect: SMB 2.0.2

        $bw.Flush()
        $smbBytes = $ms.ToArray()

        # NetBIOS Session Service header: 4 bytes, length is big-endian 24-bit
        $len = $smbBytes.Length
        $nbHdr = New-Object byte[] 4
        $nbHdr[0] = 0x00
        $nbHdr[1] = [byte](($len -shr 16) -band 0xFF)
        $nbHdr[2] = [byte](($len -shr 8)  -band 0xFF)
        $nbHdr[3] = [byte]( $len          -band 0xFF)

        $stream.Write($nbHdr, 0, 4)
        $stream.Write($smbBytes, 0, $smbBytes.Length)

        # --- Read response ---
        function _ReadExact($stream, [int]$count) {
            $buf = New-Object byte[] $count
            $read = 0
            while ($read -lt $count) {
                $n = $stream.Read($buf, $read, $count - $read)
                if ($n -le 0) { throw 'Server closed connection mid-read' }
                $read += $n
            }
            return ,$buf
        }

        $respHdr = _ReadExact $stream 4
        $respLen = ([int]$respHdr[1] -shl 16) -bor ([int]$respHdr[2] -shl 8) -bor [int]$respHdr[3]
        if ($respLen -lt 65) { throw "Response too short: $respLen bytes" }

        $respBody = _ReadExact $stream $respLen

        # SMB2 header is 64 bytes. NEGOTIATE Response body starts at offset 64.
        # NEGOTIATE Response layout (relative to body start):
        #   StructureSize       (2)  off 0
        #   SecurityMode        (2)  off 2
        #   DialectRevision     (2)  off 4
        #   NegotiateContextCount (2) off 6
        #   ServerGuid          (16) off 8
        #   ... (we stop here)
        $bodyStart = 64
        $secMode    = [BitConverter]::ToUInt16($respBody, $bodyStart + 2)
        $dialect    = [BitConverter]::ToUInt16($respBody, $bodyStart + 4)
        $guidBytes  = $respBody[($bodyStart + 8)..($bodyStart + 8 + 15)]

        $result.SigningEnabled   = (($secMode -band 0x0001) -ne 0)
        $result.SigningRequired  = (($secMode -band 0x0002) -ne 0)
        $result.DialectRevision  = ('0x{0:X4}' -f $dialect)
        $result.ServerGuid       = (New-Object Guid (,[byte[]]$guidBytes)).ToString()
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        if ($stream) { try { $stream.Dispose() } catch {} }
        if ($client) { try { $client.Close() } catch {} }
        $sw.Stop()
        $result.DurationMs = $sw.ElapsedMilliseconds
    }

    return $result
}
