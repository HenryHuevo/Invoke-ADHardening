function Invoke-ADHLdapSigningProbe {
    <#
    .SYNOPSIS
        Probes a DC over TCP/389 to determine whether LDAP signing is required.
    .DESCRIPTION
        Opens an LDAP connection and attempts an NTLM bind with signing and
        sealing explicitly DISABLED, using the current Windows credentials.
        Outcomes:

          Required    : bind rejected with LDAP_STRONG_AUTH_REQUIRED (error code 8).
                        The DC enforces signing. This is the hardened state.

          NotRequired : bind succeeded without signing. Signing is NOT enforced -
                        an attacker can relay NTLM into LDAP from this DC.

          Error       : connection / auth-other failure. Not a signal in either
                        direction; the operator should look at .Error.

        Requires only the ability to reach TCP/389 on the DC plus a valid
        Kerberos/NTLM context (any domain user works). Does NOT require local
        admin on the DC.
    .PARAMETER ComputerName
        DC hostname or FQDN to probe.
    .PARAMETER Port
        TCP port. Default 389. Use 3268 to probe the Global Catalog instead.
    .PARAMETER TimeoutSeconds
        Bind operation timeout. Default 10.
    .OUTPUTS
        PSCustomObject with: Host, Port, Result, ErrorCode, Method, Error, DurationMs.
    .EXAMPLE
        Invoke-ADHLdapSigningProbe -ComputerName dc01.corp.local
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$Port = 389,
        [int]$TimeoutSeconds = 10
    )

    $result = [PSCustomObject]@{
        Host       = $ComputerName
        Port       = $Port
        Method     = 'LDAP NTLM bind with Signing=false, Sealing=false'
        Result     = 'Error'
        ErrorCode  = $null
        Error      = $null
        DurationMs = 0
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $conn = $null
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop

        $id = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($ComputerName, $Port)
        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($id)
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Ntlm
        $conn.SessionOptions.ProtocolVersion = 3
        $conn.SessionOptions.Signing = $false
        $conn.SessionOptions.Sealing = $false
        $conn.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)

        try {
            $conn.Bind()    # uses current process Windows credentials
            $result.Result = 'NotRequired'   # DC accepted bind without signing
        }
        catch [System.DirectoryServices.Protocols.LdapException] {
            $code = $_.Exception.ErrorCode
            $result.ErrorCode = $code
            # 8 = LDAP_STRONG_AUTH_REQUIRED (a.k.a. strongAuthRequired)
            # On modern Windows DCs with signing required, you'll also occasionally
            # see 49 (invalidCredentials) - that means the bind reached auth but
            # the DC refused unsigned; treat as Required.
            if ($code -eq 8) {
                $result.Result = 'Required'
            }
            elseif ($code -eq 49 -and $_.Exception.ServerErrorMessage -match 'data 80090346|strongAuthRequired|signing') {
                $result.Result = 'Required'
            }
            else {
                $result.Error = "LdapException $code : $($_.Exception.Message)"
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        if ($conn) { try { $conn.Dispose() } catch {} }
        $sw.Stop()
        $result.DurationMs = $sw.ElapsedMilliseconds
    }

    return $result
}
