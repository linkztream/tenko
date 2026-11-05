# The push against a local HTTP listener (exit check E72): the request the exporter sends
# and what it makes of every answer of plan section 3.2 (200, 401, 403, 409, 413, 422,
# 429). The listener is plain HTTP on a loopback address, which the exporter allows only
# with -AllowPlainHttp; the certificate pin has its own suite (Guard.Tests.ps1).

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-DhcpMirror.ps1')
    . (Join-Path $PSScriptRoot 'Fixtures.ps1')
    Install-DhcpServerMock

    # A listener in its own runspace; the suite steers it through a synchronized table.
    $state = [hashtable]::Synchronized(@{ stop = $false; status = 200; body = ''; last = $null; listener = $null; port = 0 })
    $socket = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $socket.Start()
    $state.port = $socket.LocalEndpoint.Port
    $socket.Stop()
    $state.prefix = "http://127.0.0.1:$($state.port)/"
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable('state', $state)
    $worker = [powershell]::Create()
    $worker.Runspace = $runspace
    [void]$worker.AddScript({
            $listener = [System.Net.HttpListener]::new()
            $listener.Prefixes.Add($state.prefix)
            $listener.Start()
            $state.listener = $listener
            while (-not $state.stop) {
                try { $context = $listener.GetContext() } catch { break }
                $request = $context.Request
                $buffer = [System.IO.MemoryStream]::new()
                $request.InputStream.CopyTo($buffer)
                $bytes = $buffer.ToArray()
                if ($request.Headers['Content-Encoding'] -eq 'gzip') {
                    $inflated = [System.IO.MemoryStream]::new()
                    $zip = [System.IO.Compression.GZipStream]::new([System.IO.MemoryStream]::new($bytes), [System.IO.Compression.CompressionMode]::Decompress)
                    $zip.CopyTo($inflated)
                    $zip.Dispose()
                    $bytes = $inflated.ToArray()
                }
                $state.last = @{
                    method = $request.HttpMethod
                    path = $request.Url.AbsolutePath
                    authorization = $request.Headers['Authorization']
                    contentType = $request.ContentType
                    encoding = $request.Headers['Content-Encoding']
                    userAgent = $request.UserAgent
                    body = [System.Text.Encoding]::UTF8.GetString($bytes)
                    length = $bytes.Length
                }
                $response = $context.Response
                $response.StatusCode = $state.status
                $answer = [System.Text.Encoding]::UTF8.GetBytes([string]$state.body)
                $response.ContentType = $(if ($state.status -ge 400) { 'application/problem+json' } else { 'application/json' })
                $response.ContentLength64 = $answer.Length
                $response.OutputStream.Write($answer, 0, $answer.Length)
                $response.Close()
            }
            $listener.Close()
        })
    $handle = $worker.BeginInvoke()
    $deadline = [datetime]::UtcNow.AddSeconds(10)
    while ($null -eq $state.listener -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }
    if ($null -eq $state.listener) { throw 'the test listener did not start' }

    $token = ConvertTo-SecureString -String 'tnk-mirror-test-token' -AsPlainText -Force
    $body = [System.Text.Encoding]::UTF8.GetBytes('{"format":1,"sequence":7}')
    $url = "http://127.0.0.1:$($state.port)"
    function Send-Test {
        param([int]$Status, [string]$Answer, [byte[]]$Bytes = $body)
        $state.status = $Status
        $state.body = $Answer
        $state.last = $null
        return (Invoke-MirrorPush -Url $url -MirrorId 'm01' -Token $token -Body $Bytes -AllowPlainHttp 3>$null)
    }
}

AfterAll {
    $state.stop = $true
    if ($null -ne $state.listener) { $state.listener.Stop() }
    try { [void]$worker.EndInvoke($handle) } catch { Write-Verbose 'listener ended' }
    $worker.Dispose()
    $runspace.Dispose()
}

Describe 'The request' {
    It 'is a PUT of the bytes to the fixed path with the token as a bearer' {
        $result = Send-Test -Status 200 -Answer '{"sequence":7,"changed":true}'
        $result.status | Should -Be 200
        $result.sequence | Should -Be 7
        $result.changed | Should -BeTrue
        $state.last.method | Should -Be 'PUT'
        $state.last.path | Should -Be '/api/v1/migrate/mirrors/m01/snapshot'
        $state.last.authorization | Should -Be 'Bearer tnk-mirror-test-token'
        $state.last.contentType | Should -Match '^application/json'
        $state.last.body | Should -Be '{"format":1,"sequence":7}'
        $state.last.userAgent | Should -Match '^Tenko-DhcpMirror\.ps1/\d'
        $state.last.encoding | Should -BeNullOrEmpty
    }

    It 'gzips a body above one mebibyte' {
        $large = [System.Text.Encoding]::UTF8.GetBytes('{"pad":"' + ('x' * (1100 * 1024)) + '"}')
        $result = Send-Test -Status 200 -Answer '{"sequence":8,"changed":false}' -Bytes $large
        $result.status | Should -Be 200
        $result.changed | Should -BeFalse
        $state.last.encoding | Should -Be 'gzip'
        $state.last.length | Should -Be $large.Length
    }

    It 'refuses plain HTTP without the test switch, and to any address but loopback' {
        { Invoke-MirrorPush -Url $url -MirrorId 'm01' -Token $token -Body $body } | Should -Throw '*https://*'
        { Invoke-MirrorPush -Url 'http://192.0.2.53:8443' -MirrorId 'm01' -Token $token -Body $body -AllowPlainHttp 3>$null } | Should -Throw '*loopback*'
    }

    It 'builds the URL from the host and the port only' {
        (Get-SnapshotUri -Url 'https://tenko1.corp.example.test:8443/' -MirrorId '01JABC').AbsoluteUri | Should -Be 'https://tenko1.corp.example.test:8443/api/v1/migrate/mirrors/01JABC/snapshot'
        { Get-SnapshotUri -Url 'https://tenko1.corp.example.test:8443/api/v1' -MirrorId 'x' } | Should -Throw '*path*'
        { Get-SnapshotUri -Url 'ftp://tenko1.corp.example.test' -MirrorId 'x' } | Should -Throw '*https://*'
        { Get-SnapshotUri -Url 'https://tenko1.corp.example.test' -MirrorId 'a/b' } | Should -Throw '*mirror id*'
    }
}

Describe 'The answers' {
    It '401: the token is refused' {
        $result = Send-Test -Status 401 -Answer '{"type":"about:blank","status":401,"code":"auth.unauthenticated","title":"Unauthorized","detail":"the token is unknown or expired"}'
        $result.status | Should -Be 401
        $result.code | Should -Be 'auth.unauthenticated'
        $result.detail | Should -Be 'the token is unknown or expired'
    }

    It '403: the token writes another mirror' {
        $result = Send-Test -Status 403 -Answer '{"status":403,"code":"auth.forbidden","detail":"the token is scoped to another mirror"}'
        $result.status | Should -Be 403
        $result.code | Should -Be 'auth.forbidden'
    }

    It '409: the sequence is a replay, and the answer may carry the accepted one' {
        $result = Send-Test -Status 409 -Answer '{"status":409,"code":"migrate.mirror.sequence","detail":"sequence 7 is not above 1794130200","sequence":1794130200}'
        $result.status | Should -Be 409
        $result.code | Should -Be 'migrate.mirror.sequence'
        $result.sequence | Should -Be 1794130200
    }

    It '413: the body is above the bound' {
        $result = Send-Test -Status 413 -Answer '{"status":413,"code":"migrate.mirror.too_large","detail":"the body is above 8 MiB"}'
        $result.status | Should -Be 413
        $result.code | Should -Be 'migrate.mirror.too_large'
    }

    It '422: the IR does not validate, with the path of the first error' {
        $result = Send-Test -Status 422 -Answer '{"status":422,"code":"migrate.mirror.invalid","detail":"dhcp.scopes[0].reservations[3].name: not a host name"}'
        $result.status | Should -Be 422
        $result.code | Should -Be 'migrate.mirror.invalid'
        $result.detail | Should -Match '^dhcp\.scopes\[0\]'
    }

    It '429: pushed faster than the floor' {
        $result = Send-Test -Status 429 -Answer '{"status":429,"code":"sys.rate_limited","detail":"one push per 10 s"}'
        $result.status | Should -Be 429
        $result.code | Should -Be 'sys.rate_limited'
    }

    It 'keeps a non-JSON answer as the detail, cut short' {
        $result = Send-Test -Status 502 -Answer ('<html>' + ('x' * 400) + '</html>')
        $result.status | Should -Be 502
        $result.code | Should -BeNullOrEmpty
        $result.detail.Length | Should -Be 200
    }
}

Describe 'A whole run' {
    BeforeAll {
        $stateDir = Join-Path $TestDrive 'state'
        [void](New-Item -ItemType Directory -Path $stateDir)
        $configPath = Join-Path $TestDrive 'config.json'
        Set-Content -LiteralPath $configPath -Value "{`"url`":`"$url`",`"mirror`":`"m01`",`"fingerprint`":`"`"}" -Encoding ASCII
        Mock Read-MirrorToken { $token }
        Mock Test-WindowsHost { $false }
        function Invoke-Run {
            $script:ExitCode = 1
            Invoke-MirrorRun -ConfigPath $configPath -StateDir $stateDir -ServerName 'dc1.corp.example.test' -AllowPlainHttp 3>$null
            return $script:ExitCode
        }
        function Get-LastLogLine {
            $log = Get-ChildItem -LiteralPath $stateDir -Filter 'mirror-*.log' | Sort-Object Name | Select-Object -Last 1
            return (Get-Content -LiteralPath $log.FullName | Select-Object -Last 1)
        }
    }

    It 'pushes the snapshot, records the sequence and writes one log line' {
        $state.status = 200
        $state.body = '{"sequence":1,"changed":true}'
        Invoke-Run | Should -Be 0
        $sent = $state.last.body | ConvertFrom-Json
        $sent.format | Should -Be 1
        $sent.source.server | Should -Be 'dc1.corp.example.test'
        $sent.dhcp.leases.Count | Should -Be 60
        $sent.losses.entries.Count | Should -Be 13
        $sequence = (Get-Content -LiteralPath (Join-Path $stateDir 'state.json') -Raw | ConvertFrom-Json).last_sequence
        $sequence | Should -Be $sent.sequence
        $line = Get-LastLogLine
        $line | Should -Match "seq=$sequence scopes=1 reservations=30 leases=60 losses=13 hash=[0-9a-f]{16} answer=200 changed=true duration_ms=\d+"
        $line | Should -Not -Match 'tnk-mirror-test-token'
    }

    It 'pushes an unchanged snapshot again with a higher sequence; the server decides' {
        $first = (Get-Content -LiteralPath (Join-Path $stateDir 'state.json') -Raw | ConvertFrom-Json).last_sequence
        $state.body = '{"sequence":2,"changed":false}'
        Invoke-Run | Should -Be 0
        $second = (Get-Content -LiteralPath (Join-Path $stateDir 'state.json') -Raw | ConvertFrom-Json).last_sequence
        $second | Should -BeGreaterThan $first
        Get-LastLogLine | Should -Match 'changed=false'
    }

    It 'moves past the server on a replay and reports the refusal' {
        $state.status = 409
        $state.body = '{"status":409,"code":"migrate.mirror.sequence","detail":"replay","sequence":4000000000}'
        Invoke-Run | Should -Be 5
        (Get-Content -LiteralPath (Join-Path $stateDir 'state.json') -Raw | ConvertFrom-Json).last_sequence | Should -Be 4000000000
        Get-LastLogLine | Should -Match 'answer=409 code=migrate.mirror.sequence detail=replay'
        $state.status = 200
        $state.body = '{"sequence":4000000001,"changed":true}'
        Invoke-Run | Should -Be 0
        ($state.last.body | ConvertFrom-Json).sequence | Should -Be 4000000001
    }

    It 'logs a refusal and a server failure with their codes' {
        $state.status = 422
        $state.body = '{"status":422,"code":"migrate.mirror.invalid","detail":"dhcp.leases[2].ip: not an address"}'
        Invoke-Run | Should -Be 5
        Get-LastLogLine | Should -Match 'answer=422 code=migrate.mirror.invalid detail=dhcp\.leases\[2\]\.ip'
        $state.status = 503
        $state.body = '{"status":503,"code":"sys.not_ready","detail":"starting"}'
        Invoke-Run | Should -Be 6
        Get-LastLogLine | Should -Match 'answer=503 code=sys.not_ready'
    }

    It 'stops before the push without a configuration or a token' {
        { Invoke-MirrorRun -ConfigPath (Join-Path $TestDrive 'missing.json') -StateDir $stateDir -ServerName 'dc1.corp.example.test' 3>$null } | Should -Throw '*Install-TenkoDhcpMirror.ps1*'
        Mock Read-MirrorToken { throw 'no token is stored in the state directory' }
        { Invoke-Run } | Should -Throw '*no token*'
    }
}
