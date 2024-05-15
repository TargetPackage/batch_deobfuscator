import tempfile

from batch_deobfuscator.batch_interpreter import BatchDeobfuscator


# Taken from 675228b0360a56b2d3ed661635de4359d72089cb0e089eb60961727706797751
# A Grub file that contains a batch script
# The value for the variable in_check contain itself, so it create an infinite recursion when expanding it
def test_in_check_infinite_recursion():
    deobfuscator = BatchDeobfuscator()
    script = rb"""
if "%back%"=="" || set back= && set filefnd= && set in_check= ! call Fn.11 "%in_check%" "1" && exit
call Fn.11 "%in_check%" "1" && exit 1
"""
    with tempfile.TemporaryDirectory() as temp_dir:
        with tempfile.NamedTemporaryFile(dir=temp_dir) as tf:
            tf.write(script)
            tf.flush()
            deobfuscator.analyze(tf.name, temp_dir)

    # No assert, just making sure it does not error out.
