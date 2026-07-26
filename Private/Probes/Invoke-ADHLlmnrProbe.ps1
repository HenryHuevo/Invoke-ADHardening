function Invoke-ADHLlmnrProbe {
    <#
    .SYNOPSIS
        Sends an LLMNR multicast query for a nonexistent random name and
        records who, if anyone, responds.
    .DESCRIPTION
        LLMNR (RFC 4795) uses 224.0.0.252:5355 for IPv4 multicast. A host
        that has not had LLMNR disabled will respond if it thinks it owns
        the queried name - so by asking for an obviously bogus name like
        'wpad-x9k3qw' nobody legitimately owns, any response is poisoning
        behaviour (or at least responder-like behaviour).

        This is the same technique Responder's analyze mode uses; we are
        observing whether the *segment we're sitting on* has hosts that
        would answer rogue LLMNR queries. Limitations:

          - Only sees our own broadcast domain. Running from a different
            VLAN reveals nothing about the original VLAN's behaviour.
          - A 'no response in 3s' result does not prove LLMNR is disabled
            everywhere; it only proves nobody on this segment answered
            this particular query.

        We never send anything looking like real auth or trick-the-user
        traffic; we only test for responders.
    .PARAMETER QueryName
        Random name to query. Defaults to 'wpad-' + 8 random lowercase chars.
    .PARAMETER TimeoutSeconds
        How long to listen for responses. Default 3.
    .OUTPUTS
        PSCustomObject with: QueryName, RespondersCount, Responders[], Method, Error, DurationMs.
    #>
    [CmdletBinding()]
    param(
        [string]$QueryName,
        [int]$TimeoutSeconds = 3
    )

    if (-not $QueryName) {
        $suffix = -join ((1..8) | ForEach-Object { [char](Get-Random -Minimum 97 -Maximum 123) })
        $QueryName = "wpad-$suffix"
    }

    $result = [PSCustomObject]@{
        QueryName        = $QueryName
        Method           = 'LLMNR multicast query to 224.0.0.252:5355'
        RespondersCount  = 0
        Responders       = @()
        Error            = $null
        DurationMs       = 0
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $udp = $null
    try {
        # Build LLMNR query packet (DNS wire format, no compression).
        $ms = New-Object System.IO.MemoryStream
        $bw = New-Object System.IO.BinaryWriter($ms)

        $txnId = [byte[]](Get-Random -Minimum 0 -Maximum 65536),0
        # Get-Random returns one int; we want 2 bytes big-endian.
        $rnd16 = Get-Random -Minimum 0 -Maximum 65535
        $bw.Write([byte](($rnd16 -shr 8) -band 0xFF))   # TxnID high
        $bw.Write([byte]( $rnd16        -band 0xFF))   # TxnID low
        $bw.Write([byte]0x00); $bw.Write([byte]0x00)   # Flags  : standard query
        $bw.Write([byte]0x00); $bw.Write([byte]0x01)   # QDCOUNT: 1
        $bw.Write([byte]0x00); $bw.Write([byte]0x00)   # ANCOUNT
        $bw.Write([byte]0x00); $bw.Write([byte]0x00)   # NSCOUNT
        $bw.Write([byte]0x00); $bw.Write([byte]0x00)   # ARCOUNT

        # QNAME: length-prefixed labels, terminating zero. Single label is fine for LLMNR.
        $nameBytes = [System.Text.Encoding]::ASCII.GetBytes($QueryName)
        $bw.Write([byte]$nameBytes.Length)
        $bw.Write($nameBytes)
        $bw.Write([byte]0x00)                          # root label terminator

        $bw.Write([byte]0x00); $bw.Write([byte]0x01)   # QTYPE  : A
        $bw.Write([byte]0x00); $bw.Write([byte]0x01)   # QCLASS : IN

        $bw.Flush()
        $packet = $ms.ToArray()

        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.SetSocketOption(
            [System.Net.Sockets.SocketOptionLevel]::Socket,
            [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $udp.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)))
        $udp.Client.ReceiveTimeout = ($TimeoutSeconds * 1000)

        $mcast    = [System.Net.IPAddress]::Parse('224.0.0.252')
        $endpoint = New-Object System.Net.IPEndPoint($mcast, 5355)
        [void]$udp.Send($packet, $packet.Length, $endpoint)

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $seen = @{}
        while ((Get-Date) -lt $deadline) {
            try {
                $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $remoteRef = [ref]$remoteEp
                $data = $udp.Receive($remoteRef)
                if ($data -and $data.Length -gt 0) {
                    $addr = $remoteRef.Value.Address.ToString()
                    if (-not $seen.ContainsKey($addr)) {
                        $seen[$addr] = $true
                        $result.Responders += $addr
                    }
                }
            }
            catch [System.Net.Sockets.SocketException] {
                # Receive timeout - done listening.
                break
            }
        }
        $result.RespondersCount = $result.Responders.Count
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        if ($udp) { try { $udp.Close() } catch {} }
        $sw.Stop()
        $result.DurationMs = $sw.ElapsedMilliseconds
    }

    return $result
}
