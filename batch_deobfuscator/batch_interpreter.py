import argparse
import base64
import copy
import hashlib
import os
import re
import shlex
import shutil
import string
import tempfile
from collections import defaultdict
from urllib.parse import urlparse

QUOTED_CHARS = ["|", ">", "<", '"', "^", "&"]

# Powershell detection
ENC_RE = rb"(?i)(?:-|/)e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)?)?)?)?)?)?)?$"
PWR_CMD_RE = rb"(?i)(?:-|/)c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?$"
PWR_FILE_RE = rb"(?i)(?:-|/)f(?:i(?:l(?:e?)?)?)?$"

# Gathered from https://gist.github.com/api0cradle/8cdc53e2a80de079709d28a2d96458c2
RARE_LOLBAS = [
  "forfiles",
  "bash",
  "scriptrunner",
  "syncappvpublishingserver",
  "hh.exe",
  "msbuild",
  "regsvcs",
  "regasm",
  "installutil",
  "ieexec",
  "msxsl",
  "odbcconf",
  "sqldumper",
  "pcalua",
  "appvlp",
  "runscripthelper",
  "infdefaultinstall",
  "diskshadow",
  "msdt",
  "regsvr32",
]


def line_is_comment(line: str) -> bool:
    if line[:4].strip().lower() == "rem":
        return True
    # https://stackoverflow.com/questions/16632524/what-does-double-colon-mean-in-dos-batch-files
    if len(line) >= 2 and line[0] == ":" and line[1] in string.punctuation:
        return True
    return False


class BatchDeobfuscator:
    def __init__(self, complex_one_liner_threshold=4):
        self.file_path = None
        self.variables = {}
        self.exec_cmd = []
        self.exec_ps1 = []
        self.traits = defaultdict(list)
        self.complex_one_liner_threshold = complex_one_liner_threshold
        self.modified_filesystem = {}
        if os.name == "nt":
            for env_var, value in os.environ.items():
                self.variables[env_var.lower()] = value
        # fake it till you make it
        else:
            self.variables = {
              "allusersprofile": "C:\\ProgramData",
              "appdata": "C:\\Users\\puncher\\AppData\\Roaming",
              "commonprogramfiles": "C:\\Program Files\\Common Files",
              "commonprogramfiles(x86)": "C:\\Program Files (x86)\\Common Files",
              "commonprogramw6432": "C:\\Program Files\\Common Files",
              "computername": "MISCREANTTEARS",
              "comspec": "C:\\WINDOWS\\system32\\cmd.exe",
              "driverdata": "C:\\Windows\\System32\\Drivers\\DriverData",
              "errorlevel": "0",  # Because nothing fails.
              "fps_browser_app_profile_string": "Internet Explorer",
              "fps_browser_user_profile_string": "Default",
              "homedrive": "C:",
              "homepath": "\\Users\\puncher",
              "java_home": "C:\\Program Files\\Amazon Corretto\\jdk11.0.7_10",
              "localappdata": "C:\\Users\\puncher\\AppData\\Local",
              "logonserver": "\\\\MISCREANTTEARS",
              "number_of_processors": "4",
              "onedrive": "C:\\Users\\puncher\\OneDrive",
              "os": "Windows_NT",
              "path": (
                "C:\\Program Files\\Amazon Corretto\\jdk11.0.7_10\\bin;C:\\WINDOWS\\system32;"
                "C:\\WINDOWS;C:\\WINDOWS\\System32\\Wbem;C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\;"
                "C:\\Program Files\\dotnet\\;C:\\Program Files\\Microsoft SQL Server\\130\\Tools\\Binn\\;"
                "C:\\Users\\puncher\\AppData\\Local\\Microsoft\\WindowsApps;"
                "%USERPROFILE%\\AppData\\Local\\Microsoft\\WindowsApps;"
              ),
              "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
              "processor_architecture": "AMD64",
              "processor_identifier": "Intel Core Ti-83 Family 6 Model 158 Stepping 10, GenuineIntel",
              "processor_level": "6",
              "processor_revision": "9e0a",
              "programdata": "C:\\ProgramData",
              "programfiles": "C:\\Program Files",
              "programfiles(x86)": "C:\\Program Files (x86)",
              "programw6432": "C:\\Program Files",
              "psmodulepath": "C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules\\",
              "public": "C:\\Users\\Public",
              "random": "4",  # https://xkcd.com/221/
              "sessionname": "Console",
              "systemdrive": "C:",
              "systemroot": "C:\\WINDOWS",
              "temp": "C:\\Users\\puncher\\AppData\\Local\\Temp",
              "tmp": "C:\\Users\\puncher\\AppData\\Local\\Temp",
              "userdomain": "MISCREANTTEARS",
              "userdomain_roamingprofile": "MISCREANTTEARS",
              "username": "puncher",
              "userprofile": "C:\\Users\\puncher",
              "windir": "C:\\WINDOWS",
              "__compat_layer": "DetectorsMessageBoxErrors",
            }

        # There are 211 lines coming out of curl --help, so I won't be parsing all the options
        self.curl_parser = argparse.ArgumentParser()
        # Data could be had multiple time, but since we don't use it, we can ignore it
        self.curl_parser.add_argument("-d", "--data", dest="data", help="Data to send")
        self.curl_parser.add_argument("-o", "--output", dest="output", help="Write to file instead of stdout")
        self.curl_parser.add_argument("-H", "--header", dest="header", help="Extra header to include")
        self.curl_parser.add_argument(
          "-X", "--request", dest="command", default="GET", help="Specifies a custom request method"
        )
        self.curl_parser.add_argument(
          "-O",
          "--remote-name",
          dest="remote_name",
          action="store_true",
          help="Write output to a file named as the remote file",
        )
        self.curl_parser.add_argument("url", help="URL")
        # Patch all possible one-character arguments
        for char in string.ascii_letters + string.digits + "#:":
            try:
                self.curl_parser.add_argument(f"-{char}", action="store_true")
            except argparse.ArgumentError:
                pass

        self.powershell_invoke_webrequest_parser = argparse.ArgumentParser()
        # We may need to handle all possible casing for those
        self.powershell_invoke_webrequest_parser.add_argument("-uri", dest="uri")
        self.powershell_invoke_webrequest_parser.add_argument("-outfile", dest="outfile")


    def read_logical_line(self, path):
        with open(path, "r", encoding="utf-8", errors="ignore") as input_file:
            logical_line = ""
            for line in input_file:
                if not line.endswith("^"):
                    logical_line += line
                    yield logical_line
                    logical_line = ""
                else:
                    logical_line += line + "\n"


    def find_closing_paren(self, statement):
        state = "init"
        counter = 0
        start_command = 0
        for char in statement:
            # print(f"C:{char}, S:{state}")
            if state == "init":
                if char == '"':
                    # Quote is on
                    state = "quote_start"
                elif char == "^":
                    state = "escape"
                elif char == ")":
                    return statement[start_command:counter]
            elif state == "quote_start":
                if char == '"':
                    state = "init"
            elif state == "escape":
                state = "init"

            counter += 1

        return statement


    def split_if_statement(self, statement):
        # TODO: Wrapping everything in () is wrong, but helps to analyze internal elements
        if_statement = (
          r"(?P<conditional>(?P<if_statement>if)\s+(not\s+)?"
          r"(?P<type>errorlevel\s+\d+\s+|exist\s+(\".*\"|[^\s]+)\s+|.+?==.+?\s+|"
          r"(\/i\s+)?[^\s]+\s+(equ|neq|lss|leq|gtr|geq)\s+[^\s]+\s+|cmdextversion\s+\d\s+|defined\s+[^\s]+\s+)"
          r"(?P<open_paren>\()?)(?P<true_statement_start>.*)"
        )
        else_statement = (
          r"(?P<close_paren>\))?(\s+else\s+(?P<open_paren>\()?\s*(?P<false_statement_start>.*)(?P<ending_paren>\))?)"
        )
        if_match = re.search(if_statement, statement, re.IGNORECASE)
        if if_match is not None:
            true_statement_start = if_match.span("true_statement_start")[0]
            rest = statement[true_statement_start:]
            true_statement = self.find_closing_paren(rest)
            conditional = if_match.group("conditional")
            if if_match.group("open_paren") is None:
                conditional = f"{conditional}("
            yield conditional
            if true_statement.strip() == "":
                # If we are analysing only the first part, we're done after this
                return
            yield true_statement
            else_match = re.search(
              else_statement, statement[true_statement_start + len(true_statement) :], re.IGNORECASE
            )
            if else_match is None:
                if statement[true_statement_start + len(true_statement) :]:
                    yield statement[true_statement_start + len(true_statement) :]
                if if_match.group("open_paren") is None:  # or match.group("close_paren") is not None:
                    yield ")"
            else:
                # Got an ELSE statement
                else_open_paren = else_match.group("open_paren")
                if if_match.group("if_statement") == "if":
                    yield ") else ("
                else:
                    yield ") ELSE ("

                if else_open_paren is not None:
                    false_statement = self.find_closing_paren(
                      statement[
                        true_statement_start + len(true_statement) + else_match.span("false_statement_start")[0] :
                      ]
                    )
                else:
                    false_statement = statement[
                      true_statement_start + len(true_statement) + else_match.span("false_statement_start")[0] :
                    ]
                yield false_statement
                yield ")"
        else:
            # Broken statement, maybe a re-run
            yield statement


    def split_for_statement(self, statement):
        for_statement = (
          r"(?P<loop>(?P<for_statement>for)\s+"
          r"(?P<parameter>.+)"
          r"\s+IN\s+\((?P<in_set>[^\)]+)\)"
          r"\s+DO\s+"
          r"(?P<open_paren>\()?)(?P<command>[^\)]*)(?P<close_paren>\))?"
        )
        match = re.search(for_statement, statement, re.IGNORECASE)
        if match is not None:
            loop = match.group("loop")
            if match.group("open_paren") is None:
                loop = f"{loop}("
            yield loop
            yield match.group("command")
            if match.group("open_paren") is None or match.group("close_paren") is not None:
                yield ")"
        else:
            # Broken statement, maybe a re-run
            yield statement


    def get_commands_special_statement(self, statement):
        if statement.lower().startswith("if "):
            for part in self.split_if_statement(statement):
                if part.strip() != "":
                    yield part
        elif statement.lower().startswith("for "):
            for part in self.split_for_statement(statement):
                if part.strip() != "":
                    yield part
        else:
            yield statement


    def get_commands(self, logical_line):
        if line_is_comment(logical_line):
            yield logical_line.strip()
            return
        state = "init"
        counter = 0
        start_command = 0
        for char in logical_line:
            # print(f"C:{char}, S:{state}")
            if state == "init":
                if char == '"':
                    # Quote is on
                    state = "quote_start"
                elif char == "^":
                    state = "escape"
                elif char == "&" and logical_line[counter - 1] == ">":
                    # Usually an output redirection, we want to keep it on the same line
                    pass
                elif char == "&" or char == "|":
                    cmd = logical_line[start_command:counter].strip()
                    if cmd != "":
                        for part in self.get_commands_special_statement(cmd):
                            yield part
                    start_command = counter + 1
            elif state == "quote_start":
                if char == '"':
                    state = "init"
            elif state == "escape":
                state = "init"

            counter += 1

        # Remove leading spaces and trailing newlines
        last_com = logical_line[start_command:].lstrip(" ").rstrip("\n")
        if last_com != "":
            for part in self.get_commands_special_statement(last_com):
                yield part


    def get_value(self, variable):
        # This is where instances of a variable are replaced by their value
        str_substitution = (
          r"([%!])(?P<variable>[\"^|!\w#$'()*+,-.?@\[\]`{}~\s+]+)"
          r"("
          r"(:~\s*(?P<index>[+-]?\d+)\s*(?:,\s*(?P<length>[+-]?\d+))?\s*)|"
          r"(:(?P<s1>[^=]+)=(?P<s2>[^=]*))"
          r")?(\1)"
        )
        matches = re.finditer(str_substitution, variable, re.MULTILINE)

        value = ""
        for matchNum, match in enumerate(matches):
            var_name = match.group("variable").lower()
            if var_name in self.variables:
                value = self.variables[var_name]
                if match.group("index") is not None:
                    index = int(match.group("index"))
                    if index < 0 and -index >= len(value):
                        index = 0
                    elif index < 0:
                        index = len(value) + index
                    if match.group("length") is not None:
                        length = int(match.group("length"))
                    else:
                        length = len(value) - index
                    if length >= 0:
                        value = value[index : index + length]
                    else:
                        value = value[index:length]
                elif match.group("s1") is not None:
                    s1 = match.group("s1")
                    s2 = match.group("s2")
                    if s1.startswith("*") and s1[1:].lower() in value.lower():
                        value = f"{s2}{value[value.lower().index(s1[1:].lower())+len(s1)-1:]}"
                    else:
                        pattern = re.compile(re.escape(s1), re.IGNORECASE)
                        value = pattern.sub(re.escape(s2), value)
            else:
                # It should be "variable", and interpret the empty echo later, but that would need a better simulator
                return value

        if value == "^":
            return value
        return value.rstrip("^")


    def interpret_set(self, cmd):
        state = "init"
        option = None
        var_name = ""
        var_value = ""
        quote = None
        old_state = None
        stop_parsing = len(cmd)

        for idx, char in enumerate(cmd):
            # print(f"{idx}. C: {char} S: {state}, {var_value}")
            if idx >= stop_parsing:
                break
            if state == "init":
                if char == " ":
                    continue
                elif char == "/":
                    state = "option"
                elif char == '"':
                    quote = '"'
                    stop_parsing = cmd.rfind('"')
                    if idx == stop_parsing:
                        stop_parsing = len(cmd)
                    state = "var"
                elif char == "^":
                    old_state = state
                    state = "escape"
                else:
                    state = "var"
                    var_name += char
            elif state == "option":
                option = char.lower()
                state = "init"
            elif state == "var":
                if char == "=":
                    state = "value"
                elif not quote and char == '"':
                    quote = '"'
                    var_name += char
                elif char == "^":
                    old_state = state
                    state = "escape"
                else:
                    var_name += char
            elif state == "value":
                if char == "^":
                    old_state = state
                    state = "escape"
                else:
                    var_value += char
            elif state == "escape":
                if old_state == "init":
                    if char == '"':
                        quote = '^"'
                        stop_parsing = cmd.rfind('"')
                        if idx == stop_parsing:
                            stop_parsing = len(cmd)
                        state = "init"
                        old_state = None
                    else:
                        state = "var"
                        var_name += char
                        old_state = None
                elif old_state == "var":
                    if quote == '"' and char in QUOTED_CHARS:
                        var_name += "^"
                    if not quote and char == '"':
                        quote = '^"'
                    var_name += char
                    state = old_state
                    old_state = None
                elif old_state == "value":
                    var_value += char
                    state = old_state
                    old_state = None

        if option == "a":
            # Arithmetic expression: https://ss64.com/nt/set.html#expressions
            var_name = var_name.strip(" ")
            for char in QUOTED_CHARS:
                var_name = var_name.replace(char, "")
            var_value = f"({var_value.strip(' ')})"
        elif option == "p":
            last_quote_index = max(var_value.rfind("'"), var_value.rfind('"'))
            set_in = var_value.rfind("<")
            set_out = var_value.rfind(">")

            if set_out != -1 and set_out > last_quote_index:
                file_redirect = var_value[set_out:].lstrip(">").strip()
                content = var_value[:set_out].strip()
                if set_in != -1 and set_in < set_out:
                    content = var_value[:set_in].strip()
                elif set_in > set_out:
                    file_redirect = file_redirect[: set_in - set_out - 1]
                if content[0] == content[-1] in ["'", '"']:
                    content = content[1:-1].strip()
                file_redirect = file_redirect.strip()
                self.modified_filesystem[file_redirect.lower()] = {"type": "content", "content": content}
                self.traits["setp-file-redirection"].append((cmd, file_redirect))

            if set_in == -1 or set_in < last_quote_index:
                var_value = "__input__"
            else:
                # We can recover the value right away
                actual_value = var_value[set_in:].lstrip("<")
                if set_out > set_in:
                    actual_value = actual_value[: set_out - set_in - 1]
                actual_value = actual_value.strip()
                if actual_value == "nul":
                    var_value = ""
                else:
                    # We could get a value from the redirection, but for the moment we'll leave it generic
                    var_value = "__input__"

        var_name = var_name.lstrip(" ")
        if not quote:
            var_name = var_name.lstrip('^"').replace('^"', '"')

        return (var_name, var_value)


    def interpret_curl(self, cmd):
        # Batch specific obfuscation that is not handled before for echo/variable purposes, can be stripped here
        cmd = cmd.replace('""', "")
        try:
            split_cmd = shlex.split(cmd, posix=False)
        except ValueError:
            # Probably a "No closing quotation"
            # Usually generated from corrupted or non-batch files
            return
        args, unknown = self.curl_parser.parse_known_args(split_cmd[1:])

        url = args.url
        if url[0] == url[-1] in ["'", '"']:
            url = url[1:-1]

        dst = args.output
        if args.remote_name:
            dst = os.path.basename(urlparse(url).path)

        self.traits["download"].append((cmd, {"src": url, "dst": dst}))
        if dst:
            self.modified_filesystem[dst.lower()] = {"type": "download", "src": url}


    def interpret_powershell(self, normalized_comm):
        ps1_cmd = None
        # Assume the first element is the call to powershell
        cmd = normalized_comm.split()[1:]

        if cmd[0].lower() in ["invoke-webrequest", "iwr"]:
            # Parse this more similarly to curl than proper powershell
            args, unknown = self.powershell_invoke_webrequest_parser.parse_known_args(cmd[1:])
            if args.uri and args.outfile:
                self.traits["download"].append((normalized_comm, {"src": args.uri, "dst": args.outfile}))
                self.modified_filesystem[args.outfile.lower()] = {"type": "download", "src": args.uri}
                return

        for idx, part in enumerate(cmd):
            if re.match(ENC_RE, part.encode()):
                if cmd[idx + 1][0] in ["'", '"']:
                    last_part = idx + 1
                    for i in range(last_part, len(cmd)):
                        if cmd[i][-1] == cmd[idx + 1][0] and (
                            len(cmd[i]) == 1 or (len(cmd[i]) >= 2 and cmd[i][-2] != "\\")
                        ):
                            last_part = i + 1
                            break
                    try:
                        ps1_cmd = base64.b64decode(" ".join(cmd[idx + 1 : last_part])).replace(b"\x00", b"")
                    except Exception:
                        # Probably a broken script
                        return
                else:
                    try:
                        ps1_cmd = base64.b64decode(cmd[idx + 1]).replace(b"\x00", b"")
                    except Exception:
                        # Probably a broken script
                        return
                break
            
            elif re.match(PWR_CMD_RE, part.encode()):
                if cmd[idx + 1][0] in ["'", '"']:
                    last_part = idx + 1
                    for i in range(last_part, len(cmd)):
                        if cmd[i][-1] == cmd[idx + 1][0] and (
                            len(cmd[i]) == 1 or (len(cmd[i]) >= 2 and cmd[i][-2] != "\\")
                        ):
                            last_part = i + 1
                            break
                    ps1_cmd = " ".join(cmd[idx + 1 : last_part]).encode()
                else:
                    ps1_cmd = " ".join(cmd[idx + 1 :]).encode()
                break
            
            elif re.match(PWR_FILE_RE, part.encode()):
                # Found powershell execution of file, but not worth extracting the filename as a file
                return

        if ps1_cmd is None:
            last_option = 0
            for idx, part in enumerate(cmd):
                if part[0] in ["'", '"']:
                    last_part = idx + 1
                    for i in range(last_part, len(cmd)):
                        if cmd[i][-1] == part[0] and (len(cmd[i]) == 1 or (len(cmd[i]) >= 2 and cmd[i][-2] != "\\")):
                            last_part = i + 1
                            break
                    ps1_cmd = " ".join(cmd[idx:last_part]).encode()
                    break
                if part[0] in ["-", "/"]:
                    last_option = idx + 1

            if ps1_cmd is None:
                ps1_cmd = " ".join(cmd[last_option:]).encode()

        # Strip double-quotes if they are surrounding the command
        while len(ps1_cmd) > 2 and ps1_cmd[0] == 34 and ps1_cmd[-1] == 34:
            ps1_cmd = ps1_cmd[1:-1]

        if ps1_cmd:
            self.exec_ps1.append(ps1_cmd)


    def interpret_mshta(self, cmd):
        self.traits["mshta"].append(cmd)


    def interpret_rundll32(self, cmd):
        # The command is supposed to be split on "," but we're getting rid of them earlier.
        # If we every fix the loss of commas, we need to fix this split.
        split_cmd = cmd.split(" ")
        if split_cmd[1].lower() in self.modified_filesystem:
            rundll_struct = {}
            if self.modified_filesystem[split_cmd[1].lower()]["type"] == "download":
                rundll_struct["url"] = self.modified_filesystem[split_cmd[1].lower()]["src"]
            self.traits["rundll32-execution"].append((cmd, rundll_struct))


    def interpret_copy(self, cmd):
        split_cmd = []
        curr = ""
        q = ""
        for c in cmd.split():
            if not q and c[0] in ["'", '"']:
                q = c[0]
                if curr:
                    curr = f"{curr} {c}"
                else:
                    curr = c
            elif q and c[-1] == q:
                curr = f"{curr} {c}"
                split_cmd.append(curr)
                curr = ""
                q = ""
            elif q:
                curr = f"{curr} {c}"
            else:
                split_cmd.append(c)
        if curr:
            split_cmd.append(curr)

        general_options = ["/v", "/n", "/l", "/y", "/-y", "/z"]
        file_options = ["/a", "/b", "/d"]
        all_options = file_options + general_options + [x.upper() for x in file_options + general_options]
        split_cmd = list(filter(lambda x: x not in all_options, split_cmd))
        if len(split_cmd) != 3:
            # Won't follow the patttern "copy src dst", which we are currently looking at
            return

        src = re.sub(r"\\+", r"\\", split_cmd[1])
        dst = re.sub(r"\\+", r"\\", split_cmd[2])

        if src.lower().startswith("c:\\windows\\system32") and not dst.lower().startswith("c:\\windows\\system32"):
            self.traits["windows-util-manipulation"].append((cmd, {"src": src, "dst": dst}))
        self.modified_filesystem[dst.lower()] = {"type": "file", "src": src}


    def interpret_command(self, normalized_comm):
        if line_is_comment(normalized_comm):
            return

        # We need to keep trailing spaces in case the command is "set EXP=43 ", so that the value will be "43 "
        # normalized_comm = normalized_comm.strip()

        # Remove parenthesis
        index = 0
        last = len(normalized_comm) - 1
        while index < last and (normalized_comm[index] == " " or normalized_comm[index] == "("):
            if normalized_comm[index] == "(":
                while last > index and (normalized_comm[last] == " " or normalized_comm[last] == ")"):
                    if normalized_comm[last] == ")":
                        last -= 1
                        break
                    last -= 1
            index += 1
        normalized_comm = normalized_comm[index : last + 1]

        if not normalized_comm.strip() or normalized_comm == "@":
            return

        # The "@" symbol tells the command to be less verbose, which we normally don't want.
        # Source: https://stackoverflow.com/a/21077142/6456163
        if normalized_comm[0] == "@":
            normalized_comm = normalized_comm[1:]

        normalized_comm_lower = normalized_comm.lower()
        command = normalized_comm_lower.split()[0]
        if len(normalized_comm_lower.split("/")[0]) < len(command):
            command = normalized_comm_lower.split("/")[0]

        # Some commands like `set` cannot be split by double quotes, but `cmd` and `powershell` can.
        if '""' in command:
            ori_cmd_len = len(command)
            command = command.replace('""', "")
            normalized_comm = normalized_comm[:ori_cmd_len].replace('""', "") + normalized_comm[ori_cmd_len:]
            normalized_comm_lower = (
              normalized_comm_lower[:ori_cmd_len].replace('""', "") + normalized_comm_lower[ori_cmd_len:]
            )

        if command in self.modified_filesystem:
            self.traits["manipulated-content-execution"].append((normalized_comm_lower, command))
            if self.modified_filesystem[command]["type"] == "file":
                command = self.modified_filesystem[command]["src"]

        if command == "call":
            # TODO: Not a perfect interpretation as the @ sign of the recursive command shouldn't be removed.
            # This shouldn't work:
            # call @set EXP=43
            # But this should:
            # call set EXP=43
            self.interpret_command(normalized_comm[5:])
            return

        if command == "start":
            start_re = (
              r"start(.exe)?"
              r"(\/min|\/max|\/wait|\/low|\/normal|\/abovenormal|\/belownormal|\/high|\/realtime|\/b|\/i|\/w|\s+)*"
              # TODO: Add Node + Affinity options
              # TODO: Add title + path keys
              r"(?P<cmd>.*)"
            )
            match = re.match(start_re, normalized_comm, re.IGNORECASE)
            if match is not None and match.group("cmd") is not None:
                self.interpret_command(match.group("cmd"))
            return

        if command.endswith("cmd") or command.endswith("cmd.exe"):
            cmd_command = r"cmd(.exe)?\s*((\/A|\/U|\/Q|\/D)\s+|((\/E|\/F|\/V):(ON|OFF))\s*)*(\/c|\/r)\s*(?P<cmd>.*)"
            match = re.search(cmd_command, normalized_comm, re.IGNORECASE)
            if match is not None and match.group("cmd") is not None:
                self.exec_cmd.append(match.group("cmd").strip('"'))
            return

        if command == "set":
            # Interpreting set command
            var_name, var_value = self.interpret_set(normalized_comm[3:])
            if var_value == "":
                if var_name.lower() in self.variables:
                    del self.variables[var_name.lower()]
            else:
                self.variables[var_name.lower()] = var_value
            return

        if command.endswith("curl") or command.endswith("curl.exe"):
            self.interpret_curl(normalized_comm)

        if command.endswith("powershell") or command.endswith("powershell.exe"):
            # In case the target executable is a copy/lnk to powershell.exe, makes it simpler to parse the command
            patch_cmd = normalized_comm.lstrip(command)
            self.interpret_powershell(f"powershell.exe {patch_cmd}")

        if command.endswith("mshta") or command.endswith("mshta.exe"):
            self.interpret_mshta(normalized_comm)

        if command.endswith("rundll32") or command.endswith("rundll32.exe"):
            self.interpret_rundll32(normalized_comm)

        if command == "copy":
            self.interpret_copy(normalized_comm)


    def valid_percent_tilde(self, argument):
        return argument == "%" or (argument.startswith("%~") and all(x in "fdpnxsatz" for x in argument[2:]))


    def percent_tilde(self, argument):
        if argument[:2] == "%":
            return "script.bat"
        value = ""
        argument = argument[2:]
        path = ""
        if "a" in argument:
            value += "--a-------- "

        if "f" in argument:
            path = "C:\\Users\\al\\Downloads\\script.bat"
        else:
            if "d" in argument:
                path += "C:"
            if "p" in argument:
                path += "\\Users\\al\\Downloads\\"
            if "n" in argument:
                path += "script"
            if "x" in argument:
                path += ".bat"

        if "s" in argument:
            # TODO: Supposed to change the meaning of the path to a 8.3 Short name (if it exists)
            if not path:
                path = "C:\\Users\\al\\Downloads\\script.bat"

        if "t" in argument:
            value += "12/30/2022 11:41 AM "

        if "z" in argument:
            if self.file_path:
                try:
                    value += str(os.path.getsize(self.file_path))
                except Exception:
                    value += "700 "
            else:
                value += "700 "

        value += path
        value = value.strip()

        return value if value else "script.bat"


    def normalize_command(self, command):
        if line_is_comment(command):
            return command
        
        # `@echo off` is a special command that disables the echoing of commands,
        # so we want to remove it so the script is more verbose
        if command == "@echo off":
            return "REM @echo off"

        state = "init"
        normalized_com = ""
        stack = []
        traits = {"start_with_var": False, "var_used": 0}
        for char in command:
            # print(f"C:{char} S:{state} N:{normalized_com}")
            if state == "init":
                if char == '"':
                    # Quote is on
                    state = "quote_start"
                    normalized_com += char
                elif char == "," or char == ";":
                    # commas (",") are replaced by spaces, unless they are part of a string in doublequotes
                    # semicolons (";") are replaced by spaces, unless they are part of a string in doublequotes
                    # http://www.robvanderwoude.com/parameters.php
                    normalized_com += " "
                elif char == "^":
                    # Next character must be escaped
                    stack.append(state)
                    state = "escape"
                elif char == "%":
                    # Normal variable start
                    variable_start = len(normalized_com)
                    normalized_com += char
                    stack.append(state)
                    state = "normal_var_start"
                elif char == "!":
                    # Delayed variable start, difference from `%` above is explained here:
                    # https://stackoverflow.com/a/14347131/6456163
                    variable_start = len(normalized_com)
                    normalized_com += char
                    stack.append(state)
                    state = "delayed_var_start"
                else:
                    normalized_com += char

            elif state == "quote_start":
                if char == '"':
                    state = "init"
                    normalized_com += char
                elif char == "%":
                    variable_start = len(normalized_com)
                    normalized_com += char
                    stack.append("quote_start")
                    # Track that we are inside a normal variable
                    state = "normal_var_start"
                elif char == "!":
                    variable_start = len(normalized_com)
                    normalized_com += char
                    stack.append("quote_start")
                    # Track that we are inside a delayed execution variable
                    state = "delayed_var_start"
                elif char == "^":
                    state = "escape"
                    stack.append("quote_start")
                else:
                    normalized_com += char

            elif state == "normal_var_start":
                if char == "%" and normalized_com[-1] != char:
                    normalized_com += char
                    value = self.get_value(normalized_com[variable_start:])
                    normalized_com = normalized_com[:variable_start]
                    if len(normalized_com) == 0:
                        traits["start_with_var"] = True
                    normalized_com += self.normalize_command(value)
                    traits["var_used"] += 1
                    state = stack.pop()
                elif char == "%":
                    # Two `%` chars in a row
                    normalized_com += char
                    state = stack.pop()
                elif char == "=" and normalized_com[-1] == "%":
                    # `%=` is used for undocumented dynamic variables, which cannot be used with `set`
                    # due to the `=` character being used as a delimiter. It is most commonly seen in
                    # `%=exitcodeAscii%` in conjunction with `set /a` to get the exit code of the last
                    # command, usually ran by `cmd /c` for further obfuscation.
                    # More info: https://ss64.com/nt/syntax-variables.html
                    normalized_com += char
                    state = "inside_dynamic_var"
                elif char == "^":
                    # Do not escape in vars?
                    # state = "escape"
                    # stack.append("normal_var_start")
                    normalized_com += char
                elif char == "*" and len(normalized_com) == variable_start + 1:
                    # `%*` is a special variable that expands to all the parameters passed to the script,
                    # which is usually used to forward the parameters to another script.
                    normalized_com = normalized_com[:variable_start]
                    state = stack.pop()
                elif char.isdigit() and self.valid_percent_tilde(normalized_com[variable_start:]):
                    # https://www.programming-books.io/essential/batch/-percent-tilde-f4263820c2db41e399c77259970464f1.html
                    # TODO: %~$PATH:0 is not handled.
                    # normalized_com += char # is this really needed?
                    if char == "0":
                        value = self.percent_tilde(normalized_com[variable_start:])
                    else:
                        # Assume no parameter were passed
                        value = ""
                    normalized_com = normalized_com[:variable_start]
                    normalized_com += value
                    state = stack.pop()
                else:
                    normalized_com += char

            elif state == "delayed_var_start":
                if char == "!" and normalized_com[-1] != char:
                    normalized_com += char
                    value = self.get_value(normalized_com[variable_start:])
                    normalized_com = normalized_com[:variable_start]
                    if len(normalized_com) == 0:
                        traits["start_with_var"] = True
                    normalized_com += self.normalize_command(value)
                    traits["var_used"] += 1
                    state = stack.pop()
                elif char == "!":
                    normalized_com += char
                elif char == "^":
                    state = "escape"
                    stack.append("delayed_var_start")
                else:
                    normalized_com += char
            
            elif state == "inside_dynamic_var":
                if char == "%":
                    normalized_com += char
                    state = stack.pop()
                else:
                    normalized_com += char

            elif state == "escape":
                if char in QUOTED_CHARS:
                    normalized_com += "^"
                normalized_com += char
                state = stack.pop()
                if char == "%":
                    if state == "normal_var_start":
                        value = self.get_value(normalized_com[variable_start:])
                        normalized_com = normalized_com[:variable_start]
                        if len(normalized_com) == 0:
                            traits["start_with_var"] = True
                        normalized_com += self.normalize_command(value)
                        traits["var_used"] += 1
                        state = stack.pop()
                    else:
                        variable_start = len(normalized_com) - 1
                        stack.append(state)
                        state = "normal_var_start"
                elif char == "!":
                    if state == "delayed_var_start":
                        value = self.get_value(normalized_com[variable_start:])
                        normalized_com = normalized_com[:variable_start]
                        if len(normalized_com) == 0:
                            traits["start_with_var"] = True
                        normalized_com += self.normalize_command(value)
                        traits["var_used"] += 1
                        state = stack.pop()
                    else:
                        variable_start = len(normalized_com) - 1
                        stack.append(state)
                        state = "delayed_var_start"

        if state in ["normal_var_start", "delayed_var_start"]:
            normalized_com = normalized_com[:variable_start] + normalized_com[variable_start + 1 :]
        elif state == "escape":
            normalized_com += "^"

        if traits["start_with_var"]:
            self.traits["start_with_var"].append((command, normalized_com))
        self.traits["var_used"].append((command, normalized_com, traits["var_used"]))

        return normalized_com


    def analyze_logical_line(self, logical_line, working_directory, f, extracted_files):
        commands = self.get_commands(logical_line)
        for command in commands:
            normalized_comm = self.normalize_command(command)
            if len(list(self.get_commands(normalized_comm))) > 1:
                self.traits["command-grouping"].append({"Command": command, "Normalized": normalized_comm})
                self.analyze_logical_line(normalized_comm, working_directory, f, extracted_files)
            else:
                self.interpret_command(normalized_comm)
                f.write(normalized_comm)
                f.write("\r\n")
                for lolbas in RARE_LOLBAS:
                    if lolbas in normalized_comm:
                        self.traits["LOLBAS"].append({"LOLBAS": lolbas, "Command": normalized_comm})
                        
                if len(self.exec_cmd) > 0:
                    for child_cmd in self.exec_cmd:
                        child_deobfuscator = copy.deepcopy(self)
                        child_deobfuscator.exec_cmd.clear()
                        child_fd, child_path = tempfile.mkstemp(suffix=".bat", prefix="child_", dir=working_directory)
                        with open(child_path, "w") as child_f:
                            child_deobfuscator.analyze_logical_line(
                              child_cmd, working_directory, child_f, extracted_files
                            )
                        with open(child_path, "rb") as cmd_f:
                            sha256hash = hashlib.sha256(cmd_f.read()).hexdigest()
                        bat_filename = f"{sha256hash[0:10]}.bat"
                        shutil.move(child_path, os.path.join(working_directory, bat_filename))
                        extracted_files["batch"].append((bat_filename, sha256hash))
                    self.exec_cmd.clear()

                if len(self.exec_ps1) > 0:
                    for child_ps1 in self.exec_ps1:
                        sha256hash = hashlib.sha256(child_ps1).hexdigest()
                        if any(
                          extracted_file_hash == sha256hash
                          for _, extracted_file_hash in extracted_files.get("powershell", [])
                        ):
                            continue
                        powershell_filename = f"{sha256hash[0:10]}.ps1"
                        powershell_file_path = os.path.join(working_directory, powershell_filename)
                        with open(powershell_file_path, "wb") as ps1_f:
                            ps1_f.write(child_ps1)
                        extracted_files["powershell"].append((powershell_filename, sha256hash))
                    self.exec_ps1.clear()


    def analyze(self, file_path, working_directory):
        extracted_files = defaultdict(list)
        self.file_path = file_path

        file_name = "deobfuscated_bat.bat"
        temp_path = os.path.join(working_directory, file_name)
        with open(temp_path, "w") as f:
            for logical_line in self.read_logical_line(file_path):
                self.analyze_logical_line(logical_line, working_directory, f, extracted_files)

        # Figure out if we're dealing with a Complex One-Liner
        # Ignore empty lines to determine if it is a One-Liner
        self.traits["one-liner"] = False
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            firstline = False
            for line in f:
                if line.strip():
                    if not firstline:
                        self.traits["one-liner"] = True
                        firstline = True
                    else:
                        self.traits["one-liner"] = False
                        break

        with open(temp_path, "rb") as f:
            deobfuscated_data = f.read()
            if self.traits["one-liner"]:
                resulting_line_count = deobfuscated_data.count(b"\n")
                if resulting_line_count >= self.complex_one_liner_threshold:
                    self.traits["complex-one-liner"] = resulting_line_count
            sha256hash = hashlib.sha256(deobfuscated_data).hexdigest()
            bat_filename = f"{sha256hash[0:10]}_deobfuscated.bat"
            shutil.move(temp_path, os.path.join(working_directory, bat_filename))

        self.file_path = None
        return bat_filename, extracted_files


def interpret_logical_line(deobfuscator, logical_line, tab=""):
    commands = deobfuscator.get_commands(logical_line)
    for command in commands:
        normalized_comm = deobfuscator.normalize_command(command)
        deobfuscator.interpret_command(normalized_comm)
        print(tab + normalized_comm)
        if len(deobfuscator.exec_cmd) > 0:
            print(tab + "[CHILD CMD]")
            for child_cmd in deobfuscator.exec_cmd:
                child_deobfuscator = copy.deepcopy(deobfuscator)
                child_deobfuscator.exec_cmd.clear()
                interpret_logical_line(child_deobfuscator, child_cmd, tab=tab + "\t")
            deobfuscator.exec_cmd.clear()
            print(tab + "[END OF CHILD CMD]")


def interpret_logical_line_str(deobfuscator, logical_line, tab=""):
    str = ""
    commands = deobfuscator.get_commands(logical_line)
    for command in commands:
        normalized_comm = deobfuscator.normalize_command(command)
        deobfuscator.interpret_command(normalized_comm)
        str = str + tab + normalized_comm
        if len(deobfuscator.exec_cmd) > 0:
            str = str + tab + "[CHILD CMD]"
            for child_cmd in deobfuscator.exec_cmd:
                child_deobfuscator = copy.deepcopy(deobfuscator)
                child_deobfuscator.exec_cmd.clear()
                interpret_logical_line(child_deobfuscator, child_cmd, tab=tab + "\t")
            deobfuscator.exec_cmd.clear()
            str = str + tab + "[END OF CHILD CMD]"
    return str


# NOTE: This function is not used anywhere in this file, but is exported to add the
# ability to deobfuscate a batch file from another script. This essentially acts as
# the library portion of the deobfuscator.
def handle_bat_file(deobfuscator, fpath):
    strs = []
    if os.path.isfile(fpath):
        try:
            for logical_line in deobfuscator.read_logical_line(fpath):
                try:
                    strs.append(interpret_logical_line_str(deobfuscator, logical_line))
                except Exception as e:
                    print(e)
                    pass
        except Exception as e:
            print(e)
            pass
    if strs:
        return "\r\n".join(strs)
    else:
        return ""


# NOTE: This is the portion that is used when the script is run directly,
# and is not used when the script is imported as a library.
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, help="The path of obfuscated batch file")
    args = parser.parse_known_args()

    deobfuscator = BatchDeobfuscator()

    if args[0].file is not None:
        file_path = args[0].file
        for logical_line in deobfuscator.read_logical_line(args[0].file):
            interpret_logical_line(deobfuscator, logical_line)
            
    else:
        print("Please enter an obfuscated batch command:")
        interpret_logical_line(deobfuscator, input())
