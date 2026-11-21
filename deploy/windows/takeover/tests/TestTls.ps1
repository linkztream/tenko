# Shared by the suites: certificates made in memory (no trust store is touched; a served chain
# passes through the user's intermediate store and leaves it on close) and a TLS server on a
# loopback port in a runspace of its own, which answers each connection with the bytes the
# suite sets and records what it was sent.

function Get-TestCertificate {
    # A certificate authority, or a leaf it signs (with its private key, to serve TLS).
    param([string]$Subject, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Issuer, [switch]$Ca, [string[]]$Names = @(), [string[]]$Addresses = @())
    $key = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$Subject", $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($Ca.IsPresent, $false, 0, $true))
    $usage = $(if ($Ca) { [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'KeyCertSign, CrlSign' } else { [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature, KeyEncipherment' })
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage, $true))
    if (-not $Ca) {
        $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        foreach ($name in $Names) { $san.AddDnsName($name) }
        foreach ($address in $Addresses) { $san.AddIpAddress([System.Net.IPAddress]::Parse($address)) }
        $request.CertificateExtensions.Add($san.Build())
        $eku = [System.Security.Cryptography.OidCollection]::new()
        [void]$eku.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
        $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $false))
    }
    $from = [datetimeoffset]::UtcNow.AddMinutes(-5)
    $to = [datetimeoffset]::UtcNow.AddDays(1)
    if ($null -eq $Issuer) { $made = $request.CreateSelfSigned($from, $to) }
    else {
        $serial = [byte[]]::new(8)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($serial)
        $serial[0] = $serial[0] -band 0x7f
        $made = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($request.Create($Issuer, $from, $to, $serial), $key)
    }
    # Through PKCS#12 so that Schannel can use the key to serve TLS.
    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($made.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, 'test'), 'test',
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'Exportable, UserKeySet')
}

function Open-TestTlsServer {
    # Returns the control table: set .answer (bytes) and .delayMs, read .request (bytes).
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Chain = @())
    $control = [hashtable]::Synchronized(@{ queue = [System.Collections.Queue]::Synchronized([System.Collections.Queue]::new()); certs = [System.Collections.Queue]::Synchronized([System.Collections.Queue]::new()); log = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new()); served = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new()); stop = $false; answer = [byte[]]@(); delayMs = 0; request = $null; requests = 0; port = 0; ready = $false; error = '' })
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $control.port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $control.listener = $listener
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable('control', $control)
    $runspace.SessionStateProxy.SetVariable('certificate', $Certificate)
    $runspace.SessionStateProxy.SetVariable('chain', $Chain)
    $worker = [powershell]::Create()
    $worker.Runspace = $runspace
    [void]$worker.AddScript({
            $control.ready = $true
            while (-not $control.stop) {
                try { $client = $control.listener.AcceptTcpClient() } catch { break }
                try {
                    $ssl = [System.Net.Security.SslStream]::new($client.GetStream(), $false)
                    # A connection may present another identity than the server's own (.certs).
                    $serve = $certificate; $with = $chain
                    if ($control.certs.Count -gt 0) { $next = $control.certs.Dequeue(); $serve = $next.Cert; $with = $next.Chain }
                    $with = @($with | Where-Object { $null -ne $_ })
                    if ($with.Count -gt 0) {
                        # .NET on Windows adds these to the user's intermediate store (CurrentUser\CA) to
                        # send them; Close-TestTlsServer takes them out again.
                        foreach ($c in $with) { [void]$control.served.Add($c.Thumbprint) }
                        $options = [System.Net.Security.SslServerAuthenticationOptions]::new()
                        $options.ServerCertificateContext = [System.Net.Security.SslStreamCertificateContext]::Create($serve, [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new([System.Security.Cryptography.X509Certificates.X509Certificate2[]]$with), $true)
                        $ssl.AuthenticateAsServerAsync($options, [System.Threading.CancellationToken]::None).Wait()
                    } else {
                        $ssl.AuthenticateAsServer($serve)
                    }
                    $buffer = [System.IO.MemoryStream]::new()
                    $chunk = [byte[]]::new(8192)
                    while ($true) {
                        $read = $ssl.Read($chunk, 0, $chunk.Length)
                        if ($read -le 0) { break }
                        $buffer.Write($chunk, 0, $read)
                        $text = [System.Text.Encoding]::ASCII.GetString($buffer.ToArray())
                        $end = $text.IndexOf("`r`n`r`n")
                        if ($end -ge 0) {
                            $length = 0
                            if ($text -match 'Content-Length: (\d+)') { $length = [int]$Matches[1] }
                            if ($buffer.Length -ge $end + 4 + $length) { break }
                        }
                    }
                    $control.request = $buffer.ToArray()
                    $control.requests++
                    if ($control.delayMs -gt 0) { Start-Sleep -Milliseconds $control.delayMs }
                    [void]$control.log.Add($control.request)
                    $answer = $(if ($control.queue.Count -gt 0) { [byte[]]$control.queue.Dequeue() } else { [byte[]]$control.answer })
                    $ssl.Write($answer, 0, $answer.Length)
                    $ssl.Flush()
                    $ssl.Dispose()
                } catch {
                    $control.error = $_.Exception.Message
                } finally {
                    $client.Dispose()
                }
            }
        })
    $control.handle = $worker.BeginInvoke()
    $control.worker = $worker
    $control.runspace = $runspace
    return $control
}

function Close-TestTlsServer {
    param([hashtable]$Control)
    $Control.stop = $true
    $Control.listener.Stop()
    try { [void]$Control.worker.EndInvoke($Control.handle) } catch { Write-Verbose 'the server ended' }
    $Control.worker.Dispose()
    $Control.runspace.Dispose()
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('CA', 'CurrentUser')
    $store.Open('ReadWrite')
    try { foreach ($c in @($store.Certificates | Where-Object { $Control.served -contains $_.Thumbprint })) { $store.Remove($c) } } finally { $store.Dispose() }
}

function Get-TestAnswer {
    # An HTTP answer with a JSON body unless told otherwise.
    param([int]$Status = 200, [string]$Body = '{}', [string]$Type = 'application/json', [string[]]$Headers = @(), [switch]$NoLength)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $head = "HTTP/1.1 $Status X`r`nContent-Type: $Type`r`n"
    if (-not $NoLength) { $head += "Content-Length: $($bytes.Length)`r`n" }
    foreach ($header in $Headers) { $head += "$header`r`n" }
    $head += "Connection: close`r`n`r`n"
    return , ([System.Text.Encoding]::ASCII.GetBytes($head) + $bytes)
}
