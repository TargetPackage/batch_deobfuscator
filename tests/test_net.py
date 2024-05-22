import tempfile

from batch_deobfuscator.batch_interpreter import BatchDeobfuscator


def test_net_user():
    deobfuscator = BatchDeobfuscator()
    deobfuscator.interpret_command("net user")
    assert len(deobfuscator.traits) == 0
    deobfuscator.interpret_command("net user guest")
    assert len(deobfuscator.traits) == 0
    deobfuscator.interpret_command("net user administrator")
    assert len(deobfuscator.traits) == 0


def test_net_use_user_password():
    deobfuscator = BatchDeobfuscator()
    cmd = "net use Q: https://webdav.site.com passw'd /user:username@site.com"
    deobfuscator.interpret_command(cmd)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["net-use"]) == 1
    assert deobfuscator.traits["net-use"][0] == (
        cmd,
        {
            "devicename": "Q:",
            "server": "https://webdav.site.com",
            "password": "passw'd",
            "user": "username@site.com",
        },
    )


def test_net_use_user():
    deobfuscator = BatchDeobfuscator()
    cmd = r"net use d: \\server\share /user:Accounts\User1"
    deobfuscator.interpret_command(cmd)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["net-use"]) == 1
    assert deobfuscator.traits["net-use"][0] == (
        cmd,
        {
            "devicename": "d:",
            "server": r"\\server\share",
            "user": r"Accounts\User1",
        },
    )


def test_net_use_no_devicename():
    deobfuscator = BatchDeobfuscator()
    cmd = r"NET USE C:\TEMP\STUFF"
    deobfuscator.interpret_command(cmd)
    assert len(deobfuscator.traits) == 1
    print(deobfuscator.traits)
    assert len(deobfuscator.traits["net-use"]) == 1
    assert deobfuscator.traits["net-use"][0] == (
        cmd,
        {
            "server": r"C:\TEMP\STUFF",
        },
    )


def test_net_use_delete():
    deobfuscator = BatchDeobfuscator()
    cmd = r"NET USE X: /DELETE"
    deobfuscator.interpret_command(cmd)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["net-use"]) == 1
    assert deobfuscator.traits["net-use"][0] == (
        cmd,
        {
            "devicename": "X:",
            "options": ["delete"],
        },
    )

    cmd = r"NET USE U: /DELETE /y"
    deobfuscator.interpret_command(cmd)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["net-use"]) == 2
    assert deobfuscator.traits["net-use"][1] == (
        cmd,
        {
            "devicename": "U:",
            "options": ["delete", "auto-accept"],
        },
    )


def test_net_use_delete_with_server():
    deobfuscator = BatchDeobfuscator()
    cmd = r"net use f: \\financial\public /delete"
    deobfuscator.interpret_command(cmd)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["net-use"]) == 1
    assert deobfuscator.traits["net-use"][0] == (
        cmd,
        {
            "devicename": "f:",
            "server": r"\\financial\public",
            "options": ["delete"],
        },
    )


def test_net_use_missing_var():
    # Probably something like
    # net use %UNKNOWN_VAR% /delete
    # Which gets resolved to
    # net use  /delete
    deobfuscator = BatchDeobfuscator()
    cmd = r"net use  /delete"
    deobfuscator.interpret_command(cmd)
    assert len(deobfuscator.traits) == 0


def test_net_use_redirect():
    deobfuscator = BatchDeobfuscator()
    cmd = r"NET USE U: \\server\files >> output.log"
    deobfuscator.interpret_command(cmd)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["net-use"]) == 1
    assert deobfuscator.traits["net-use"][0] == (
        cmd,
        {
            "devicename": "U:",
            "server": r"\\server\files",
        },
    )


def test_net_use_space():
    deobfuscator = BatchDeobfuscator()
    cmd = r'net use g: "\\server.local\some\path\to\a nice folder" /user:domain\username'
    deobfuscator.interpret_command(cmd)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["net-use"]) == 1
    assert deobfuscator.traits["net-use"][0] == (
        cmd,
        {
            "devicename": "g:",
            "server": r"\\server.local\some\path\to\a nice folder",
            "user": r"domain\username",
        },
    )


def test_net_use_script():
    deobfuscator = BatchDeobfuscator()
    script = rb"""
net use w: /delete >nul 2>nul
if not exist w: (
	net use w: \\server\files /Persistent:NO >nul 2>nul
	)
"""
    with tempfile.TemporaryDirectory() as temp_dir:
        with tempfile.NamedTemporaryFile(dir=temp_dir) as tf:
            tf.write(script)
            tf.flush()
            deobfuscator.analyze(tf.name, temp_dir)

    assert "net-use" in deobfuscator.traits
    assert len(deobfuscator.traits["net-use"]) == 2
    assert deobfuscator.traits["net-use"][0] == (
        r"net use w: /delete >nul 2>nul",
        {
            "devicename": "w:",
            "options": ["delete"],
        },
    )
    assert deobfuscator.traits["net-use"][1] == (
        r"net use w: \\server\files /Persistent:NO >nul 2>nul",
        {
            "devicename": "w:",
            "server": r"\\server\files",
            "options": ["not-persistent"],
        },
    )
