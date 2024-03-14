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
