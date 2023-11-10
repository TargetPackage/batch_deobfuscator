# Introduction
> By using this Python script, you can deobfuscate a batch script that is obfuscated with string substitution, escape character techniques, and more.

Original project by [DissectMalware](https://github.com/DissectMalware), additional modifications made by [gdesmar](https://github.com/gdesmar). We just expanded functionality and added additional commentary to the codebase to make the deobfuscation process easier to understand.

**NOTE: This should ONLY be ran on a virtual machine in an isolated environment to minimize the risk of accidental damage to your system. The creators of this tool are not responsible for any damage caused by its usage.**

## Running the script
To run the script:

```shell
python3 batch_interpreter.py --file c:\test\obfuscated_file.bat
```

### Options
```shell
$ python3 batch_interpreter.py --help
usage: batch_interpreter.py [-h] [-f FILE] [-o OUTPUT] [-v] [-m] [-e]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The path of obfuscated batch file
  -o OUTPUT, --output OUTPUT
                        The path the deobfuscated batch file should be written
                        to (default: stdout)
  -v, --verbose         Whether to include additional information in the
                        output, such as child commands and comments
  -m, --math            Whether to attempt to execute mathematical operations
                        in the batch file
  -e, --exitcodes       Whether to attempt to store command exit codes and
                        replace `%=exitcodeAscii%` with the appropriate value
```

## Use as a lib
```python
from batch_deobfuscator.batch_interpreter import BatchDeobfuscator, handle_bat_file
deobfuscator = BatchDeobfuscator()
deobfuscated_script = handle_bat_file(deobfuscator, "./obfuscated_file.bat")
```

## Developing

### Setup
```shell
$ git clone https://github.com/TargetPackage/batch_deobfuscator
$ cd batch_deobfuscator
$ pip3 install -e ".[dev]"
```

### Testing
```shell
$ python3 -m pytest
```

Add `-v` for extra information, useful if tests are failing and you aren't sure why.
