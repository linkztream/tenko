# The HTTP helper and the TLS check (MIG-17): JSON only, no redirect, size and time capped,
# the root built from the presented certificates by signature verification with the host
# name matched, and the check run as a script block on both editions. A TLS server on a
# loopback port answers what each test sets. Windows PowerShell's server side (Schannel)
# sends the leaf alone, so there the chain is checked by its own tests below and the
# handshake's check is answered for the server's chain; PowerShell 7 sends the whole chain,
# which on Windows passes through the user's intermediate store while the server runs.

BeforeDiscovery {
    $core = $PSVersionTable.PSEdition -eq 'Core'
}

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1')
    . (Join-Path $PSScriptRoot 'TestTls.ps1')
    $script:TkVersion = '0.0.0-test'
    $ca = Get-TestCertificate -Subject 'Tenko CA' -Ca
    $leaf = Get-TestCertificate -Subject 'localhost' -Issuer $ca -Names 'localhost' -Addresses '127.0.0.1'
    $otherCa = Get-TestCertificate -Subject 'Interceptor CA' -Ca
    $otherLeaf = Get-TestCertificate -Subject 'localhost' -Issuer $otherCa -Names 'localhost'
    $caPin = ConvertTo-TkHex (Get-TkSha256 $ca.RawData)
    $otherPin = ConvertTo-TkHex (Get-TkSha256 $otherCa.RawData)
    $core = $PSVersionTable.PSEdition -eq 'Core'
    $server = Open-TestTlsServer -Certificate $leaf -Chain $(if ($core) { @($ca) } else { @() })
    $mocked = @($leaf.Thumbprint, $otherLeaf.Thumbprint)
    if (-not $core) {
        # The handshake's check only (Schannel reports the leaf's chain as untrusted there);
        # the chain's own tests below pass other errors and reach the real function.
        Mock Test-TkServerChain -ParameterFilter { $mocked -contains $Leaf.Thumbprint -and ($Errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors) -ne 0 } {
            $root = $(if ($Leaf.Thumbprint -eq $otherLeaf.Thumbprint) { $otherPin } else { $caPin })
            @{ Ok = ($Pinned -eq '' -or $Pinned -eq $root); RootSha256 = $root; Failure = 'the chain ends in another root than the pinned one'; MachineTrusted = $false }
        }
    }
    function Use-TestConnection {
        param([string]$Pinned = '')
        $script:TkConn.Host = 'localhost'
        $script:TkConn.Port = $server.port
        $script:TkConn.Address = [System.Net.IPAddress]::Loopback
        $script:TkConn.Local = $null
        $script:TkConn.Pinned = $Pinned
        $script:TkConn.Session = $null
    }
    function Get-RequestText { [System.Text.Encoding]::ASCII.GetString([byte[]]$server.request) }
}

AfterAll { Close-TestTlsServer $server }

Describe 'The request' {
    BeforeEach { Use-TestConnection; $server.delayMs = 0 }

    It 'is HTTP/1.0 to the fixed path, JSON, with the session as a bearer and the body as given' {
        $server.answer = Get-TestAnswer -Body '{"a":1}'
        $secret = [securestring]::new(); foreach ($c in 'tnka_0123456789abcdefABCDEF'.ToCharArray()) { $secret.AppendChar($c) }
        $script:TkConn.Session = $secret
        $answer = Invoke-TkHttp -Method POST -Path '/api/v1/migrate/mirrors' -Body ([System.Text.Encoding]::ASCII.GetBytes('{"x":true}'))
        $answer.Status | Should -Be 200
        $answer.Json.a | Should -Be 1
        $text = Get-RequestText
        $text | Should -Match '^POST /api/v1/migrate/mirrors HTTP/1\.0\r\n'
        $text | Should -Match "\r\nAuthorization: Bearer tnka_0123456789abcdefABCDEF\r\n"
        $text | Should -Match '\r\nContent-Type: application/json\r\nContent-Length: 10\r\n'
        $text | Should -Match '\r\n\r\n\{"x":true\}$'
    }

    It 'sends no session where none is wanted' {
        $server.answer = Get-TestAnswer
        $secret = [securestring]::new(); $secret.AppendChar('x')
        $script:TkConn.Session = $secret
        [void](Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession)
        Get-RequestText | Should -Not -Match 'Authorization'
    }

    It 'refuses a path that is not the API''s' {
        { Invoke-TkHttp -Method GET -Path 'http://elsewhere/' } | Should -Throw '*not one the script sends*'
        { Invoke-TkHttp -Method GET -Path "/api/v1/x`r`nHost: y" } | Should -Throw '*not one the script sends*'
    }
}

Describe 'The answer' {
    BeforeEach { Use-TestConnection; $server.delayMs = 0 }

    It 'refuses an answer that is not JSON' {
        $server.answer = Get-TestAnswer -Body '<html>hi</html>' -Type 'text/html'
        { Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession } | Should -Throw '*not JSON*'
    }

    It 'refuses malformed JSON, and JSON followed by text' {
        $server.answer = Get-TestAnswer -Body '{"a":'
        { Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession } | Should -Throw '*JSON*'
        $server.answer = Get-TestAnswer -Body '{"a":1} {"b":2}'
        { Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession } | Should -Throw '*follows the JSON*'
    }

    It 'follows no redirect' {
        $server.answer = Get-TestAnswer -Status 302 -Headers @('Location: https://elsewhere.example.test/')
        { Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession } | Should -Throw '*redirect*'
    }

    It 'refuses a truncated answer' {
        $bytes = Get-TestAnswer -Body '{"a":"0123456789"}'
        $server.answer = $bytes[0..($bytes.Length - 5)]
        { Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession } | Should -Throw '*truncated*'
    }

    It 'refuses an oversized answer' {
        $server.answer = Get-TestAnswer -Body ('{"a":"' + ('x' * (4MB + 70000)) + '"}') -NoLength
        { Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession } | Should -Throw '*larger than 4 MiB*'
    }

    It 'prints a problem''s code and detail without control or format characters' {
        $server.answer = Get-TestAnswer -Status 422 -Type 'application/problem+json' -Body '{"code":"x.y\u001b[2K","detail":"bad\nline\r\u202eevil\u0007"}'
        $answer = Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession
        $answer.Status | Should -Be 422
        $answer.Code | Should -Be 'x.y [2K'
        $answer.Detail | Should -Be 'bad line  evil'
        $answer.Detail | Should -Not -Match '\p{Cc}'
        $answer.Detail.Contains([string][char]0x202e) | Should -BeFalse
    }

    It 'names a refusal of the delegated session as such' {
        $server.answer = Get-TestAnswer -Status 403 -Type 'application/problem+json' -Body '{"code":"auth.delegation.refused","status":403,"detail":"outside the allow-list"}'
        { Invoke-Tenko -Method POST -Path '/dns/zones' -Body ([ordered]@{ name = 'corp.example.test' }) } | Should -Throw "*auth.delegation.refused*does not open POST /dns/zones to a takeover's session*"
    }

    It 'reads the CA root as PEM only where asked' {
        $pem = "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($ca.RawData))`n-----END CERTIFICATE-----`n"
        $server.answer = Get-TestAnswer -Body $pem -Type 'application/x-pem-file'
        (Invoke-TkHttp -Method GET -Path '/api/v1/system/ca-root' -Pem -NoSession).Text | Should -Be $pem
        { Invoke-TkHttp -Method GET -Path '/api/v1/system/ca-root' -NoSession } | Should -Throw '*not JSON*'
    }
}

Describe 'The TLS check' {
    BeforeEach { Use-TestConnection; $server.answer = Get-TestAnswer; $server.delayMs = 0 }

    It 'runs during the handshake and records the root it built' {
        [void](Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession)
        $script:TkConn.LastTls.RootSha256 | Should -Be $caPin
    }

    It 'refuses a connection whose chain ends in another root than the pinned one' {
        Use-TestConnection -Pinned ('0' * 64)
        { Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession } | Should -Throw '*TLS*'
    }

    It 'accepts a chain the server presents that ends in a self-signed authority' {
        $chain = Test-TkServerChain -Leaf $leaf -Presented @($ca) -Errors 'None' -Pinned ''
        $chain.Ok | Should -BeTrue
        $chain.RootSha256 | Should -Be $caPin
    }

    It 'refuses a partial chain' {
        $chain = Test-TkServerChain -Leaf $leaf -Presented @() -Errors 'None' -Pinned ''
        $chain.Ok | Should -BeFalse
        $chain.Failure | Should -Not -BeNullOrEmpty -Because 'Windows PowerShell may find a cached certificate of the same name, whose signature then fails'
    }

    It 'takes the root an interceptor''s chain ends in, never the real root it appends' {
        $chain = Test-TkServerChain -Leaf $otherLeaf -Presented @($otherCa, $ca) -Errors 'None' -Pinned ''
        $chain.Ok | Should -BeTrue
        $chain.RootSha256 | Should -Be (ConvertTo-TkHex (Get-TkSha256 $otherCa.RawData))
        $pinned = Test-TkServerChain -Leaf $otherLeaf -Presented @($otherCa, $ca) -Errors 'None' -Pinned $caPin
        $pinned.Ok | Should -BeFalse
        $pinned.Failure | Should -Match 'not the pinned one'
    }

    It 'refuses a leaf that does not match the host name, and a leaf that is its own root' {
        (Test-TkServerChain -Leaf $leaf -Presented @($ca) -Errors 'RemoteCertificateNameMismatch' -Pinned '').Failure | Should -Match 'host name'
        (Test-TkServerChain -Leaf $ca -Presented @($ca) -Errors 'None' -Pinned '').Failure | Should -Match 'leaf'
        (Test-TkServerChain -Leaf $null -Presented @() -Errors 'None' -Pinned '').Ok | Should -BeFalse
    }

    It 'builds the server''s whole chain in the handshake' -Skip:(-not $core) {
        # Runner: PowerShell 7 only, whose server side sends the chain (Windows PowerShell's
        # Schannel server sends the leaf alone).
        Use-TestConnection -Pinned $caPin
        (Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession).Status | Should -Be 200
        $script:TkConn.LastTls.Ok | Should -BeTrue
    }
}

Describe 'The approval''s pin' {
    It 'refuses a collect that reaches another root than the approval request, and collects nothing' {
        Use-TestConnection
        $script:TkVersion = '0.0.0-test'
        $nonce = ConvertTo-TkBase64Url ([byte[]](1..32))
        $server.queue.Clear(); $server.certs.Clear()
        $server.queue.Enqueue((Get-TestAnswer -Status 201 -Body "{`"id`":`"0190d1c2-0000-7000-8000-00000000a001`",`"nonce`":`"$nonce`"}"))
        $server.queue.Enqueue((Get-TestAnswer -Body '{"secret":"tnka_0123456789abcdefABCDEF","delegation":"0190d1c2-0000-7000-8000-00000000d001"}'))
        # The approval request reaches Tenko's chain; the first collect an interceptor's.
        $server.certs.Enqueue(@{ Cert = $leaf; Chain = $(if ($core) { @($ca) } else { @() }) })
        $server.certs.Enqueue(@{ Cert = $otherLeaf; Chain = $(if ($core) { @($otherCa) } else { @() }) })
        $before = $server.requests
        $failure = $null
        try { [void](Request-TkApproval -Plan ([ordered]@{ domain = 'corp.example.test' }) -Domain 'corp.example.test' 6>$null) } catch { $failure = $_.Exception }
        $failure | Should -Not -BeNullOrEmpty
        $failure.Message | Should -Match 'another TLS root than the approval request'
        $failure.Data['tk.exit'] | Should -Be 4
        ($server.requests - $before) | Should -Be 1 -Because 'nothing was sent over the interceptor''s connection'
        $script:TkConn.Session | Should -BeNullOrEmpty
        $server.queue.Clear(); $server.certs.Clear()
    }
}

Describe 'An older node' {
    # A server that presents its leaf alone, as Tenko's API listener did before it presented
    # its root: refused on both editions, by the real check, with a sentence that says why.
    BeforeAll {
        # An authority of its own: the main server's passes through the user's intermediate
        # store, where the client's chain engine would find it.
        $oldCa = Get-TestCertificate -Subject 'Older CA' -Ca
        $old = Open-TestTlsServer -Certificate (Get-TestCertificate -Subject 'localhost' -Issuer $oldCa -Names 'localhost' -Addresses '127.0.0.1')
        $old.answer = Get-TestAnswer
    }
    AfterAll {
        Close-TestTlsServer $old
    }

    It 'is refused, naming the root it did not present' {
        Use-TestConnection
        $script:TkConn.Port = $old.port
        { Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession } | Should -Throw '*presented its leaf certificate alone, without the root*older node*'
    }
}

Describe 'The chain build' {
    It 'fetches no issuer from a URL the leaf names, on PowerShell 7 in the handshake and in the script''s own build' {
        # Read from the file: on 5.1 the suite replaces Test-TkServerChain by a mock.
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path -Parent $PSScriptRoot) 'Tenko-Takeover.ps1'), [ref]$tokens, [ref]$errors)
        $functions = @{}
        foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $functions[$node.Name] = $node.Extent.Text }
        $functions['Invoke-TkHttp'] | Should -Match 'CertificateChainPolicy\.DisableCertificateDownloads = \$true'
        $functions['Test-TkServerChain'] | Should -Match 'ChainPolicy\.DisableCertificateDownloads = \$true'
    }
}

Describe 'A slow answer' {
    # Last, since the server keeps sleeping after the client gave up.
    It 'is refused after the time cap' {
        Use-TestConnection
        $script:TkHttpTimeoutMs = 10000
        $server.delayMs = 14000
        $server.answer = Get-TestAnswer
        { Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession } | Should -Throw
        $server.delayMs = 0
        $script:TkHttpTimeoutMs = 30000
    }
}
