# The install script (exit check E72): the checks on its inputs, what it writes, and the
# task it registers under the given account. The ScheduledTasks cmdlets are stubs here
# (they declare the cmdlets' parameters and use none, hence the two suppressions); the
# token's DPAPI round trip runs on Windows only.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'stubs of the ScheduledTasks cmdlets')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Register-ScheduledTask takes -User and -Password')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Register-ScheduledTask takes -Password as text')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'stubs of the New-ScheduledTask* cmdlets')]
param()

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Install-TenkoDhcpMirror.ps1')
    $password = ConvertTo-SecureString -String 'a-long-random-password' -AsPlainText -Force
    $credential = [pscredential]::new('CORP\svc-tenko-mirror', $password)

    function New-ScheduledTaskAction { param($Execute, $Argument) return [pscustomobject]@{ Execute = $Execute; Argument = $Argument } }
    function New-ScheduledTaskTrigger { param([switch]$Once, $At, $RepetitionInterval) return [pscustomobject]@{ At = $At; Interval = $RepetitionInterval } }
    function New-ScheduledTaskSettingsSet { param($MultipleInstances, $ExecutionTimeLimit, [switch]$StartWhenAvailable, [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, [switch]$DontStopOnIdleEnd, $Compatibility) return [pscustomobject]@{ MultipleInstances = $MultipleInstances; ExecutionTimeLimit = $ExecutionTimeLimit } }
    function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) return [pscustomobject]@{ UserId = $UserId; LogonType = $LogonType; RunLevel = $RunLevel } }
    function Get-ScheduledTask { [CmdletBinding()] param($TaskName, $TaskPath) }
    function Unregister-ScheduledTask { [CmdletBinding(SupportsShouldProcess)] param($TaskName, $TaskPath) if ($PSCmdlet.ShouldProcess($TaskName)) { $null = $TaskPath } }
    function Register-ScheduledTask { param($TaskName, $TaskPath, $Action, $Trigger, $Settings, $Principal, $User, $Password, $RunLevel) }
}

Describe 'The inputs' {
    It 'takes the controller as host and port over https only' {
        Test-ControllerUrl 'https://tenko1.corp.example.test:8443/' | Should -Be 'https://tenko1.corp.example.test:8443'
        Test-ControllerUrl 'https://192.0.2.53:8443' | Should -Be 'https://192.0.2.53:8443'
        { Test-ControllerUrl 'http://tenko1.corp.example.test:8443' } | Should -Throw '*https://*'
        { Test-ControllerUrl 'https://tenko1.corp.example.test:8443/api/v1' } | Should -Throw '*path*'
        { Test-ControllerUrl 'https://user:secret@tenko1.corp.example.test' } | Should -Throw '*credentials*'
    }

    It 'stores the fingerprint as colon-separated uppercase pairs' {
        ConvertTo-FingerprintText ('ab' * 32) | Should -Be (('AB:' * 31) + 'AB')
        ConvertTo-FingerprintText ('AB:' * 31 + 'AB') | Should -Be (('AB:' * 31) + 'AB')
        { ConvertTo-FingerprintText 'ABCD' } | Should -Throw '*64 hexadecimal*'
    }

    It 'checks the mirror id' {
        Test-MirrorId '01JC3V9Q7E' | Should -Be '01JC3V9Q7E'
        { Test-MirrorId 'a b' } | Should -Throw
        { Test-MirrorId '' } | Should -Throw
    }

    It 'takes a group managed service account without a credential and a user with one' {
        $gmsa = Test-AccountName -Account 'CORP\gmsa-mirror$'
        $gmsa.gmsa | Should -BeTrue
        $user = Test-AccountName -Account 'CORP\svc-tenko-mirror' -Credential $credential
        $user.gmsa | Should -BeFalse
        { Test-AccountName -Account 'CORP\svc-tenko-mirror' } | Should -Throw '*-Credential*'
        { Test-AccountName -Account 'CORP\gmsa-mirror$' -Credential $credential } | Should -Throw '*no password*'
        { Test-AccountName -Account 'svc-tenko-mirror' } | Should -Throw '*DOMAIN\name*'
        { Test-AccountName -Account 'CORP\other' -Credential $credential } | Should -Throw '*not for*'
    }
}

Describe 'What the install writes' {
    It 'writes a configuration the exporter reads' {
        $text = Get-MirrorConfigText -Url 'https://tenko1.corp.example.test:8443' -MirrorId '01JC3V9Q7E' -Fingerprint (('AB:' * 31) + 'AB')
        $config = $text | ConvertFrom-Json
        $config.url | Should -Be 'https://tenko1.corp.example.test:8443'
        $config.mirror | Should -Be '01JC3V9Q7E'
        $config.fingerprint | Should -Be (('AB:' * 31) + 'AB')
    }

    It 'leaves the token as token.pending for the first run' {
        $dir = Join-Path $TestDrive 'state'
        [void](New-Item -ItemType Directory -Path $dir -Force)
        $path = Write-PendingToken -StateDir $dir -Token (ConvertTo-SecureString -String 'tnk-mirror-token' -AsPlainText -Force)
        $path | Should -Be (Join-Path $dir 'token.pending')
        Get-Content -LiteralPath $path -Raw | Should -Be 'tnk-mirror-token'
        { Write-PendingToken -StateDir $dir -Token (ConvertTo-SecureString -String 'two words' -AsPlainText -Force) } | Should -Throw '*whitespace*'
        { Write-PendingToken -StateDir $dir -Token (ConvertTo-SecureString -String ' ' -AsPlainText -Force) } | Should -Throw '*empty*'
    }

    It 'stores the token with DPAPI for the account on the first run and deletes the plain file' -Skip:($env:OS -ne 'Windows_NT') {
        . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-DhcpMirror.ps1')
        $dir = Join-Path $TestDrive 'dpapi'
        [void](New-Item -ItemType Directory -Path $dir -Force)
        [void](Write-PendingToken -StateDir $dir -Token (ConvertTo-SecureString -String 'tnk-mirror-token' -AsPlainText -Force))
        Save-PendingToken -Dir $dir | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $dir 'token.pending') | Should -BeFalse
        $stored = Get-Content -LiteralPath (Join-Path $dir 'token.dpapi') -Raw
        $stored | Should -Not -Match 'tnk-mirror-token'
        ConvertFrom-SecureToken (Read-MirrorToken -Dir $dir) | Should -Be 'tnk-mirror-token'
        Save-PendingToken -Dir $dir | Should -BeFalse
    }

    It 'runs the exporter without a profile, non-interactively, from the installed path' {
        $arguments = Get-TaskArgumentText -ScriptPath 'C:\Program Files\Tenko\mirror\Tenko-DhcpMirror.ps1'
        $arguments | Should -Match '-NoProfile'
        $arguments | Should -Match '-NonInteractive'
        $arguments | Should -Match '-File "C:\\Program Files\\Tenko\\mirror\\Tenko-DhcpMirror\.ps1"'
        $arguments | Should -Not -Match '-Once'
    }
}

Describe 'The task' {
    BeforeAll {
        $calls = @{}
        Mock Register-ScheduledTask {
            $calls.register = @{ TaskName = $TaskName; TaskPath = $TaskPath; Action = $Action; Trigger = $Trigger; Settings = $Settings; Principal = $Principal; User = $User; Password = $Password; RunLevel = $RunLevel }
            [pscustomobject]@{ TaskName = $TaskName }
        }
        Mock Unregister-ScheduledTask { $calls.unregister = @{ TaskName = $TaskName; TaskPath = $TaskPath } }
    }

    It 'is registered every minute under a user account with its password, no highest privileges, one instance at a time' {
        Mock Get-ScheduledTask { $null }
        $calls.Clear()
        $task = Register-MirrorTask -TaskName 'Tenko DHCP mirror' -TaskPath '\Tenko\' -PowerShell 'powershell.exe' -ScriptPath 'C:\x\Tenko-DhcpMirror.ps1' `
            -AccountInfo @{ name = 'CORP\svc-tenko-mirror'; gmsa = $false } -Credential $credential
        $task.TaskName | Should -Be 'Tenko DHCP mirror'
        $calls.ContainsKey('unregister') | Should -BeFalse
        $registered = $calls.register
        $registered.User | Should -Be 'CORP\svc-tenko-mirror'
        $registered.Password | Should -Be 'a-long-random-password'
        $registered.RunLevel | Should -Be 'Limited'
        $registered.Principal | Should -BeNullOrEmpty
        $registered.Trigger.Interval.TotalSeconds | Should -Be 60
        $registered.Settings.MultipleInstances | Should -Be 'IgnoreNew'
        $registered.Settings.ExecutionTimeLimit.TotalMinutes | Should -Be 5
        $registered.Action.Execute | Should -Be 'powershell.exe'
        $registered.Action.Argument | Should -Match '-NonInteractive'
        $registered.TaskPath | Should -Be '\Tenko\'
    }

    It 'is registered under a group managed service account through a principal without a password, replacing an existing task' {
        Mock Get-ScheduledTask { [pscustomobject]@{ TaskName = $TaskName } }
        $calls.Clear()
        [void](Register-MirrorTask -TaskName 'Tenko DHCP mirror' -TaskPath '\Tenko\' -PowerShell 'pwsh.exe' -ScriptPath 'C:\x\Tenko-DhcpMirror.ps1' `
                -AccountInfo @{ name = 'CORP\gmsa-mirror$'; gmsa = $true })
        $calls.unregister.TaskName | Should -Be 'Tenko DHCP mirror'
        $registered = $calls.register
        $registered.Principal.UserId | Should -Be 'CORP\gmsa-mirror$'
        $registered.Principal.LogonType | Should -Be 'Password'
        $registered.Principal.RunLevel | Should -Be 'Limited'
        $registered.User | Should -BeNullOrEmpty
        $registered.Password | Should -BeNullOrEmpty
        $registered.Action.Execute | Should -Be 'pwsh.exe'
    }
}
