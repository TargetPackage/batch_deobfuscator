# Introduction
> By using this Python script, you can deobfuscate a batch script that is obfuscated with string substitution, escape character techniques, and more.

Original project by [DissectMalware](https://github.com/DissectMalware), additional modifications made by [gdesmar](https://github.com/gdesmar). We just expanded functionality and added additional commentary to the codebase to make the deobfuscation process easier to understand.


## Running the script
To run the script:

```shell
python3 batch_interpreter.py --file c:\test\obfuscated_file.bat
```

## Use as a lib
```python
from batch_deobfuscator.batch_interpreter import BatchDeobfuscator, handle_bat_file
deobfuscator = BatchDeobfuscator()
itsthewine=handle_bat_file(deobfuscator, "./obfuscated_file.bat")
```

## TODOs
- [ ] Fix the issue mentioned [here](https://stackoverflow.com/a/77126882/6456163); prevent expanding on Windows variables automatically?
- [ ] Combine with functionality of [this](https://github.com/danielbohannon/Invoke-DOSfuscation)
