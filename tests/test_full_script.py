import os
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


def test_concat_logical_lines():
    deobfuscator = BatchDeobfuscator()
    script = rb"""REM download log file
curl -X GET --fail ^
-H "Accept: application/octet-stream" ^
http://server.org/data?accept=data >>met\resultat\output.log"""
    with tempfile.TemporaryDirectory() as temp_dir:
        with tempfile.NamedTemporaryFile(dir=temp_dir) as tf:
            tf.write(script)
            tf.flush()
            bat_filename, _ = deobfuscator.analyze(tf.name, temp_dir)

        with open(os.path.join(temp_dir, bat_filename), "rb") as f:
            result = f.read()
    lines = result.split(b"\r\n")

    assert len(lines) >= 2
    assert lines[0] == b"REM download log file"
    assert lines[1] == (
        rb'curl -X GET --fail -H "Accept: application/octet-stream" '
        rb"http://server.org/data?accept=data >>met\resultat\output.log"
    )
