from batch_deobfuscator.batch_interpreter import BatchDeobfuscator


def test_dry_rundll32():
    deobfuscator = BatchDeobfuscator()
    cmd = r"$WINSYSDIR$\RunDLL32.exe"
    deobfuscator.interpret_command(cmd)
    assert len(deobfuscator.traits) == 0
