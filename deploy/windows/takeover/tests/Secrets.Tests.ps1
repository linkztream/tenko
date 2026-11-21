# No secret reaches a log or a transcript (MIG-17, ADR 0038): the approval, its collect, a
# request with the delegated session and the creation of a mirror, whose answer carries a
# token, run against the TLS server of TestTls.ps1 under a transcript and under a trace of
# every parameter binding (what module logging records of each command). The secrets reach
# the server, and neither file holds them.

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1')
    . (Join-Path $PSScriptRoot 'TestTls.ps1')
    $script:TkVersion = '0.0.0-test'
    $ca = Get-TestCertificate -Subject 'Tenko CA' -Ca
    $leaf = Get-TestCertificate -Subject 'localhost' -Issuer $ca -Names 'localhost' -Addresses '127.0.0.1'
    $caPin = ConvertTo-TkHex (Get-TkSha256 $ca.RawData)
    $core = $PSVersionTable.PSEdition -eq 'Core'
    $server = Open-TestTlsServer -Certificate $leaf -Chain $(if ($core) { @($ca) } else { @() })
    if (-not $core) {
        # As in Http.Tests.ps1: Windows PowerShell's Schannel server sends the leaf alone.
        Mock Test-TkServerChain -ParameterFilter { ($Errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors) -ne 0 } {
            @{ Ok = ($Pinned -eq '' -or $Pinned -eq $caPin); RootSha256 = $caPin; Failure = 'pinned elsewhere'; MachineTrusted = $false }
        }
    }
    Mock Start-Sleep { }
    $sessionSecret = 'tnka_' + ('S3cr3tSess10n' * 3)
    $mirrorToken = 'tnkc_' + ('M1rr0rT0ken' * 3)
}

AfterAll { Close-TestTlsServer $server }

Describe 'The secrets' {
    It 'reach Tenko and appear in no transcript and no trace of parameter bindings' {
        $script:TkConn.Host = 'localhost'; $script:TkConn.Port = $server.port; $script:TkConn.Address = [System.Net.IPAddress]::Loopback
        $script:TkConn.Local = $null; $script:TkConn.Pinned = ''; $script:TkConn.Session = $null
        $nonce = ConvertTo-TkBase64Url ([byte[]](1..32))
        $server.queue.Enqueue((Get-TestAnswer -Status 201 -Body "{`"id`":`"0190d1c2-0000-7000-8000-00000000a001`",`"nonce`":`"$nonce`"}"))
        $server.queue.Enqueue((Get-TestAnswer -Status 409 -Type 'application/problem+json' -Body '{"code":"auth.approval.pending","status":409}'))
        $server.queue.Enqueue((Get-TestAnswer -Body "{`"secret`":`"$sessionSecret`",`"session`":`"0190d1c2-0000-7000-8000-00000000c001`",`"delegation`":`"0190d1c2-0000-7000-8000-00000000d001`",`"expires_at`":`"2026-11-21T18:00:00Z`",`"idle_secs`":900}"))
        $server.queue.Enqueue((Get-TestAnswer -Status 201 -Body "{`"mirror`":{`"id`":`"0190d1c2-0000-7000-8000-00000000e001`"},`"token`":`"$mirrorToken`",`"ca_fingerprint`":`"`"}"))
        $server.queue.Enqueue((Get-TestAnswer -Status 204 -Body ''))
        $transcript = Join-Path $TestDrive 'transcript.txt'
        $trace = Join-Path $TestDrive 'trace.txt'
        $plan = [ordered]@{ domain = 'corp.example.test'; operations = @('mirrors') }
        Start-Transcript -LiteralPath $transcript | Out-Null
        try {
            Trace-Command -Name ParameterBinding -FilePath $trace -Expression {
                $run = Request-TkApproval -Plan $plan -Domain 'corp.example.test'
                $created = Invoke-Tenko -Method POST -Path '/migrate/mirrors' -Body ([ordered]@{ name = 'dc1.corp.example.test'; kind = 'windows-dhcp'; source_prefixes = @('192.0.2.30/32') })
                $script:created = $created
                $script:run = $run
                Close-TkSession
            } 6>&1 | Out-Host
        } finally {
            Stop-Transcript | Out-Null
        }
        $script:run | Should -Be '0190d1c2-0000-7000-8000-00000000d001'
        $script:created.token | Should -BeOfType [securestring]
        $sent = @($server.log | ForEach-Object { [System.Text.Encoding]::ASCII.GetString([byte[]]$_) }) -join "`n"
        $sent | Should -Match ([regex]::Escape("Authorization: Bearer $sessionSecret"))
        $sent | Should -Match '"signature":"[A-Za-z0-9_\-]{86}"'
        foreach ($file in $transcript, $trace) {
            $text = Get-Content -LiteralPath $file -Raw
            $text.Length | Should -BeGreaterThan 100
            $text | Should -Not -Match ([regex]::Escape($sessionSecret)) -Because "$file holds no session"
            $text | Should -Not -Match ([regex]::Escape($mirrorToken)) -Because "$file holds no token"
            $text | Should -Not -Match 'S3cr3tSess10n|M1rr0rT0ken'
        }
        (Get-Content -LiteralPath $trace -Raw) | Should -Match 'BIND' -Because 'the trace recorded the bindings'
    }

    It 'leaves the one-time password of Tenko''s account and the exporter''s password as SecureStrings' {
        $secret = Get-TkRandomSecret
        $secret | Should -BeOfType [securestring]
        $secret.Length | Should -Be 36
        $secret.IsReadOnly() | Should -BeTrue
    }
}
