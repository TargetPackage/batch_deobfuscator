from batch_deobfuscator.batch_interpreter import BatchDeobfuscator


def test_net_user():
    deobfuscator = BatchDeobfuscator()
    deobfuscator.interpret_command("net user")
    assert len(deobfuscator.traits) == 0
    deobfuscator.interpret_command("net user guest")
    assert len(deobfuscator.traits) == 0
    deobfuscator.interpret_command("net user administrator")
    assert len(deobfuscator.traits) == 0
