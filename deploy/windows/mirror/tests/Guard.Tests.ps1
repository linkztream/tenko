# The two guards of plan section 2.1: the account check (point 4) and the certificate pin
# (point 5), on both editions. The certificates are made in memory; nothing touches a
# trust store.

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-DhcpMirror.ps1')
    . (Join-Path $PSScriptRoot 'Fixtures.ps1')
    Install-DhcpServerMock

    function Get-GroupRecord {
        param([string]$Sid, [string]$Name)
        return [pscustomobject]@{ Sid = $Sid; Name = $Name }
    }
    $dhcpUsers = Get-GroupRecord -Sid 'S-1-5-21-1-2-3-1105' -Name 'CORP\DHCP Users'
    $users = Get-GroupRecord -Sid 'S-1-5-32-545' -Name 'BUILTIN\Users'
    $me = Get-GroupRecord -Sid 'S-1-5-21-1-2-3-1200' -Name 'CORP\svc-tenko-mirror'

    function Get-TestCertificate {
        # A CA or a leaf signed by it, RSA 2048, valid for a day.
        param([string]$Subject, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Issuer, [switch]$Ca)
        $key = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$Subject", $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($Ca.IsPresent, $false, 0, $true))
        $usage = $(if ($Ca) { [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign } else { [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature })
        $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage, $true))
        $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false))
        if (-not $Ca) {
            $names = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
            $names.AddDnsName($Subject)
            $request.CertificateExtensions.Add($names.Build())
        }
        $from = [datetimeoffset]::UtcNow.AddMinutes(-5)
        $to = [datetimeoffset]::UtcNow.AddDays($(if ($Ca) { 2 } else { 1 }))
        if ($null -eq $Issuer) {
            # The authority keeps its key, to sign the leaves below.
            return $request.CreateSelfSigned($from, $to)
        }
        $serial = [byte[]]::new(8)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($serial)
        $serial[0] = $serial[0] -band 0x7f
        $certificate = $request.Create($Issuer, $from, $to, $serial)
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    }

    function Get-PresentedChain {
        # The chain as the TLS layer hands it to the callback: built from the leaf and the
        # certificates the server sent, without trust.
        param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Leaf, [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Sent)
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        foreach ($certificate in $Sent) { [void]$chain.ChainPolicy.ExtraStore.Add($certificate) }
        [void]$chain.Build($Leaf)
        return $chain
    }

    $tenkoCa = Get-TestCertificate -Subject 'Tenko CA' -Ca
    $otherCa = Get-TestCertificate -Subject 'Other CA' -Ca
    $leaf = Get-TestCertificate -Subject 'tenko1.corp.example.test' -Issuer $tenkoCa
    $otherLeaf = Get-TestCertificate -Subject 'tenko1.corp.example.test' -Issuer $otherCa
    Initialize-Pin -Fingerprint ('0' * 64)
    $tenkoPin = [Tenko.Mirror.Pin]::Sha256Hex($tenkoCa.RawData)
    $none = [System.Net.Security.SslPolicyErrors]::None
    $nameMismatch = [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch
}

Describe 'The account check' {
    It 'finds Domain Admins and Enterprise Admins by their RID' {
        $found = Get-PrivilegedMembership -Groups @($users, $dhcpUsers, (Get-GroupRecord -Sid 'S-1-5-21-1-2-3-512' -Name 'CORP\Domain Admins'))
        $found | Should -Be @('CORP\Domain Admins')
        $found = Get-PrivilegedMembership -Groups @((Get-GroupRecord -Sid 'S-1-5-21-1-2-3-519' -Name ''))
        $found | Should -Be @('S-1-5-21-1-2-3-519')
    }

    It 'finds Administrators and SYSTEM by their well-known SID' {
        (Get-PrivilegedMembership -Groups @($users, (Get-GroupRecord -Sid 'S-1-5-32-544' -Name 'BUILTIN\Administrators'))) | Should -Be @('BUILTIN\Administrators')
        (Get-PrivilegedMembership -Groups @((Get-GroupRecord -Sid 'S-1-5-18' -Name 'NT AUTHORITY\SYSTEM'))) | Should -Be @('NT AUTHORITY\SYSTEM')
    }

    It 'finds DHCP Administrators and DnsAdmins by name, with or without the domain' {
        $found = Get-PrivilegedMembership -Groups @($dhcpUsers, (Get-GroupRecord -Sid 'S-1-5-21-1-2-3-1106' -Name 'CORP\DnsAdmins'), (Get-GroupRecord -Sid 'S-1-5-21-1-2-3-1107' -Name 'dhcp administrators'))
        $found | Should -Be @('CORP\DnsAdmins', 'dhcp administrators')
    }

    It 'passes a member of DHCP Users and nothing else' {
        (Get-PrivilegedMembership -Groups @($me, $users, $dhcpUsers)).Count | Should -Be 0
        (Get-PrivilegedMembership -Groups @()).Count | Should -Be 0
    }

    It 'refuses to push as a privileged account before it reads anything' {
        Mock Test-WindowsHost { $true }
        Mock Get-IdentityGroup { @($me, (Get-GroupRecord -Sid 'S-1-5-21-1-2-3-512' -Name 'CORP\Domain Admins')) }
        Mock Read-DhcpServer { throw 'must not read' }
        $stateDir = Join-Path $TestDrive 'state'
        [void](New-Item -ItemType Directory -Path $stateDir -Force)
        { Invoke-MirrorRun -StateDir $stateDir -ConfigPath (Join-Path $TestDrive 'none.json') } | Should -Throw '*CORP\Domain Admins*'
        $log = Get-ChildItem -LiteralPath $stateDir -Filter 'mirror-*.log' | Select-Object -First 1
        Get-Content -LiteralPath $log.FullName | Select-Object -Last 1 | Should -Match 'refused: this account is a member of CORP\\Domain Admins'
        Should -Invoke Read-DhcpServer -Times 0
    }

    It 'only warns for -Once, which pushes nothing' {
        Mock Test-WindowsHost { $true }
        Mock Get-IdentityGroup { @($me, (Get-GroupRecord -Sid 'S-1-5-32-544' -Name 'BUILTIN\Administrators')) }
        $output = @(Invoke-MirrorRun -Once -StateDir (Join-Path $TestDrive 'state') -ConfigPath (Join-Path $TestDrive 'none.json') -ServerName 'dc1.corp.example.test' 3>&1)
        $warnings = @($output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message })
        $json = @($output | Where-Object { $_ -is [string] }) -join "`n"
        ($json | ConvertFrom-Json).format | Should -Be 1
        ($warnings -join ' ') | Should -Match 'BUILTIN\\Administrators'
    }
}

Describe 'The fingerprint' {
    It 'takes 64 hexadecimal digits with or without colons' {
        ConvertTo-FingerprintHex ('AB:' * 31 + 'AB') | Should -Be ('ab' * 32)
        ConvertTo-FingerprintHex ('ab' * 32) | Should -Be ('ab' * 32)
        { ConvertTo-FingerprintHex ('ab' * 20) } | Should -Throw '*64 hexadecimal*'
        { ConvertTo-FingerprintHex '' } | Should -Throw '*empty*'
    }
}

Describe 'The certificate pin' {
    It 'accepts a chain that ends in the pinned certificate authority' {
        Initialize-Pin -Fingerprint $tenkoPin
        $chain = Get-PresentedChain -Leaf $leaf -Sent @($tenkoCa)
        [Tenko.Mirror.Pin]::Validate($null, $leaf, $chain, $none) | Should -BeTrue
        [Tenko.Mirror.Pin]::LastFailure | Should -BeNullOrEmpty
    }

    It 'refuses a chain that ends in another authority, and says which fingerprint it saw' {
        Initialize-Pin -Fingerprint $tenkoPin
        $chain = Get-PresentedChain -Leaf $otherLeaf -Sent @($otherCa)
        [Tenko.Mirror.Pin]::Validate($null, $otherLeaf, $chain, $none) | Should -BeFalse
        [Tenko.Mirror.Pin]::LastFailure | Should -Match ([Tenko.Mirror.Pin]::Sha256Hex($otherCa.RawData))
        [Tenko.Mirror.Pin]::LastFailure | Should -Match 'not the pinned one'
    }

    It 'refuses the right leaf when the host name does not match' {
        Initialize-Pin -Fingerprint $tenkoPin
        $chain = Get-PresentedChain -Leaf $leaf -Sent @($tenkoCa)
        [Tenko.Mirror.Pin]::Validate($null, $leaf, $chain, $nameMismatch) | Should -BeFalse
        [Tenko.Mirror.Pin]::LastFailure | Should -Match 'host name'
    }

    It 'refuses a leaf whose issuer was not presented' {
        Initialize-Pin -Fingerprint $tenkoPin
        $chain = Get-PresentedChain -Leaf $leaf -Sent @()
        [Tenko.Mirror.Pin]::Validate($null, $leaf, $chain, $none) | Should -BeFalse
        [Tenko.Mirror.Pin]::LastFailure | Should -Not -BeNullOrEmpty
    }

    It 'refuses the pinned authority presented as the leaf of another chain' {
        Initialize-Pin -Fingerprint ([Tenko.Mirror.Pin]::Sha256Hex($leaf.RawData))
        $chain = Get-PresentedChain -Leaf $leaf -Sent @($tenkoCa)
        [Tenko.Mirror.Pin]::Validate($null, $leaf, $chain, $none) | Should -BeFalse
    }

    It 'refuses everything without a pin or a certificate' {
        [Tenko.Mirror.Pin]::Fingerprint = ''
        $chain = Get-PresentedChain -Leaf $leaf -Sent @($tenkoCa)
        [Tenko.Mirror.Pin]::Validate($null, $leaf, $chain, $none) | Should -BeFalse
        [Tenko.Mirror.Pin]::LastFailure | Should -Match 'no fingerprint'
        Initialize-Pin -Fingerprint $tenkoPin
        [Tenko.Mirror.Pin]::Validate($null, $null, $null, $none) | Should -BeFalse
    }

    It 'is what the push installs for https, and nothing for the test listener' {
        Initialize-Pin -Fingerprint $tenkoPin
        $callback = [Tenko.Mirror.Pin]::Callback
        $callback | Should -BeOfType [System.Net.Security.RemoteCertificateValidationCallback]
        $chain = Get-PresentedChain -Leaf $leaf -Sent @($tenkoCa)
        $callback.Invoke($null, $leaf, $chain, $none) | Should -BeTrue
    }
}
