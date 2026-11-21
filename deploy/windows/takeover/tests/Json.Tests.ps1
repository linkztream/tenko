# The script's own JSON writer and parser (MIG-17): Tenko's answers are parsed here and
# nowhere else, strictly, and a secret field becomes a SecureString inside the parser.

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1')
    function Read-Json { param([string]$Text) ConvertFrom-TkJson -Chars $Text.ToCharArray() }
    function Write-Json { param([object]$Value) [System.Text.Encoding]::ASCII.GetString((ConvertTo-TkJsonByte $Value)) }
}

Describe 'The writer' {
    It 'writes compact JSON in the given key order, ASCII only' {
        Write-Json ([ordered]@{ b = 1; a = @('x', $true, $null); c = [ordered]@{ d = 'q"\' } }) | Should -BeExactly '{"b":1,"a":["x",true,null],"c":{"d":"q\"\\"}}'
        Write-Json ('a' + [char]0xe9 + [char]10) | Should -BeExactly '"a\u00e9\u000a"'
        Write-Json @() | Should -BeExactly '[]'
    }

    It 'writes a SecureString''s characters without making a string of it' {
        $secret = [securestring]::new(); foreach ($c in 'tnk_abc'.ToCharArray()) { $secret.AppendChar($c) }
        Write-Json ([ordered]@{ password = $secret }) | Should -BeExactly '{"password":"tnk_abc"}'
    }
}

Describe 'The parser' {
    It 'reads objects, arrays, strings with escapes, numbers, booleans and null' {
        $value = Read-Json ' { "a" : [1, -2, 3.5, 1e3, 18446744073709551615], "b": "x\"\\\/\b\f\n\r\t\u00e9", "c": true, "d": false, "e": null, "f": {} } '
        $value.a[0] | Should -Be 1
        $value.a[1] | Should -Be -2
        $value.a[2] | Should -Be 3.5
        $value.a[3] | Should -Be 1000
        $value.a[4] | Should -Be ([decimal]::Parse('18446744073709551615'))
        $value.b | Should -BeExactly ("x`"\/" + [char]8 + [char]12 + "`n`r`t" + [char]0xe9)
        $value.c | Should -BeTrue
        $value.d | Should -BeFalse
        $value.e | Should -BeNullOrEmpty
        $value.f.Count | Should -Be 0
    }

    It 'keeps an array of one and an empty array as arrays' {
        (Read-Json '{"a":[1]}').a.GetType().IsArray | Should -BeTrue
        @((Read-Json '{"a":[]}').a).Count | Should -Be 0
    }

    It 'refuses <case>' -ForEach @(
        @{ case = 'a truncated object'; text = '{"a":1' }
        @{ case = 'a truncated string'; text = '{"a":"b' }
        @{ case = 'a repeated key'; text = '{"a":1,"a":2}' }
        @{ case = 'a raw control character'; text = "{`"a`":`"b`tc`"}" }
        @{ case = 'an unknown escape'; text = '{"a":"\q"}' }
        @{ case = 'a bad \u escape'; text = '{"a":"\u12"}' }
        @{ case = 'trailing text'; text = '{} x' }
        @{ case = 'a bare word'; text = '{"a":yes}' }
        @{ case = 'a leading zero'; text = '[01]' }
        @{ case = 'nesting deeper than 64'; text = ('[' * 70) + (']' * 70) }
    ) {
        { Read-Json $text } | Should -Throw
    }

    It 'reads a top-level secret field into a SecureString and nothing else into one' {
        $value = Read-Json '{"secret":"tnka_0123456789abcdef0123","nested":{"secret":"plain"},"token":"tnkc_xyz"}'
        $value.secret | Should -BeOfType [securestring]
        $value.token | Should -BeOfType [securestring]
        $value.nested.secret | Should -BeExactly 'plain'
        Test-TkSecurePattern $value.secret $script:TkSessionPattern | Should -BeTrue
        { Read-Json ('{"secret":"a\' + 'u0041"}') } | Should -Throw '*printable ASCII*' -Because 'a secret carries no escape'
        { Read-Json '{"secret":5}' } | Should -Throw '*not a string*'
    }
}
