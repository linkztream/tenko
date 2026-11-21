# The approval code and the collect's signature against the shared test vector
# (fixtures/approval-code.json, the same file as crates/tenko-auth/tests/fixtures/), and the
# request's body as the script sends it (MIG-17).

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1')
    $vector = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/approval-code.json') -Raw | ConvertFrom-Json
    $code = $vector.code
    $collect = $vector.collect
}

Describe 'The vector' {
    It 'is the server''s own, and says which copy is newer when they differ' -Skip:(-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot '../../../../crates/tenko-auth/tests/fixtures/approval-code.json'))) {
        # Runner: a tree that holds the server's fixture (it lands with the server's approval).
        $mine = Join-Path $PSScriptRoot 'fixtures/approval-code.json'
        $server = Join-Path $PSScriptRoot '../../../../crates/tenko-auth/tests/fixtures/approval-code.json'
        $a = (Get-Content -LiteralPath $mine -Raw) -replace "`r", ''
        $b = (Get-Content -LiteralPath $server -Raw) -replace "`r", ''
        if ($a -ne $b) {
            $when = @{}
            foreach ($path in $mine, $server) { $when[$path] = [string](git -C (Split-Path -Parent $path) log -1 --format=%cI -- $path 2>$null) }
            $newer = $(if ($when[$server] -gt $when[$mine]) { "the server's ($server, $($when[$server]))" } else { "this suite's ($mine, $($when[$mine]))" })
            $a | Should -Be $b -Because "the two vectors differ; the newer is ${newer}: make them one"
        }
    }
}

Describe 'The code' {
    It 'is the vector''s code over the vector''s inputs, with every intermediate value' {
        $body = [System.Text.Encoding]::UTF8.GetBytes($code.request_body)
        ConvertTo-TkHex (Get-TkSha256 $body) | Should -Be $code.request_sha256
        ConvertTo-TkHex (ConvertFrom-TkBase64Url $code.key_base64url) | Should -Be $code.key_uncompressed
        ConvertTo-TkHex (ConvertTo-TkUuidByte $code.approval_id) | Should -Be $code.approval_id_octets
        $result = Get-TkApprovalCode -Domain $code.domain -RootSha256 (ConvertFrom-TkHex $code.root_sha256) -RequestSha256 (Get-TkSha256 $body) `
            -Key (ConvertFrom-TkHex $code.key_uncompressed) -Id $code.approval_id
        $result | Should -BeExactly $code.code
        $script:TkCodeContext | Should -BeExactly $code.context
        $script:TkAlphabet | Should -BeExactly $code.alphabet
    }

    It 'changes with the root, the body, the key and the id' {
        $args0 = @{ Domain = $code.domain; RootSha256 = (ConvertFrom-TkHex $code.root_sha256); RequestSha256 = (ConvertFrom-TkHex $code.request_sha256); Key = (ConvertFrom-TkHex $code.key_uncompressed); Id = $code.approval_id }
        $base = Get-TkApprovalCode @args0
        foreach ($field in 'RootSha256', 'RequestSha256') {
            $changed = $args0.Clone(); $changed[$field] = [byte[]]::new(32)
            Get-TkApprovalCode @changed | Should -Not -Be $base
        }
        $changed = $args0.Clone(); $changed.Id = '0190d1c2-0000-7000-8000-00000000a002'
        Get-TkApprovalCode @changed | Should -Not -Be $base
        $changed = $args0.Clone(); $changed.Domain = 'CORP.example.test.'
        Get-TkApprovalCode @changed | Should -Be $base -Because 'the domain is hashed in canonical form'
    }

    It 'refuses an approval id that is not of the exact form' {
        { ConvertTo-TkUuidByte '0190D1C2-0000-7000-8000-00000000A001' } | Should -Throw '*approval id*'
        { ConvertTo-TkUuidByte '0190d1c2000070008000-00000000a001' } | Should -Throw '*approval id*'
    }
}

Describe 'The collect' {
    It 'signs the vector''s message, which the vector''s signature verifies' {
        $nonce = ConvertFrom-TkBase64Url $collect.nonce_base64url
        ConvertTo-TkHex $nonce | Should -Be $collect.nonce
        $message = Get-TkCollectMessage -Id $code.approval_id -Nonce $nonce
        ConvertTo-TkHex $message | Should -Be $collect.message
        $point = ConvertFrom-TkHex $code.key_uncompressed
        $parameters = [System.Security.Cryptography.ECParameters]::new()
        $parameters.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
        $q = [System.Security.Cryptography.ECPoint]::new()
        $q.X = $point[1..32]
        $q.Y = $point[33..64]
        $parameters.Q = $q
        $public = [System.Security.Cryptography.ECDsa]::Create($parameters)
        $public.VerifyData($message, (ConvertFrom-TkBase64Url $collect.signature_base64url), [System.Security.Cryptography.HashAlgorithmName]::SHA256) | Should -BeTrue
    }

    It 'signs with a key of its own that verifies as r || s of 64 octets' {
        $key = Get-TkRunKey
        $point = Get-TkPublicPoint $key
        $point.Length | Should -Be 65
        $point[0] | Should -Be 4
        $message = Get-TkCollectMessage -Id $code.approval_id -Nonce (ConvertFrom-TkHex $collect.nonce)
        $signature = $key.SignData($message, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $signature.Length | Should -Be 64
        $key.VerifyData($message, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256) | Should -BeTrue
        $key.Dispose()
    }
}

Describe 'The request' {
    It 'is the four fields with the plan as given, ASCII, the bytes that are hashed' {
        $plan = [ordered]@{ domain = 'corp.example.test'; operations = @('mirrors') }
        $script:TkVersion = '0.1.0'
        $bytes = ConvertTo-TkApprovalBody -Plan $plan -Key (ConvertFrom-TkHex $code.key_uncompressed) -Machine 'ADM1' -User 'CORP\admin'
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        $text | Should -BeExactly ('{"purpose":"windows-takeover","plan":{"domain":"corp.example.test","operations":["mirrors"]},"key":"' + $code.key_base64url + '","client":{"machine":"ADM1","user":"CORP\\admin","version":"0.1.0"}}')
    }
}
