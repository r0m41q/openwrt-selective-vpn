from pathlib import Path
import shlex
import sys


def quote(value):
    return "'" + value.replace("'", "'\\''") + "'"


def export(path):
    lexer = shlex.shlex(Path(path).read_text(), posix=True, punctuation_chars="\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    commands = []
    current = []
    for token in lexer:
        if token and not token.strip("\n"):
            if current:
                commands.append(current)
            current = []
        else:
            current.append(token)
    if current:
        commands.append(current)
    lines = []
    section = False
    for command in commands:
        if command[0] == "package" and len(command) == 2:
            continue
        if command[0] == "config" and len(command) in (2, 3):
            name = " " + quote(command[2]) if len(command) == 3 else ""
            lines.append("config " + command[1] + name + "\n")
            section = True
        elif command[0] in ("option", "list") and len(command) == 3 and section:
            lines.append("\t" + command[0] + " " + command[1] + " " + quote(command[2]) + "\n")
        else:
            raise ValueError("invalid fixture input")
    return "package fixture\n\n" + "".join(lines)


if __name__ == "__main__":
    try:
        print(export(sys.argv[1]), end="")
    except (ValueError, IndexError):
        sys.exit(1)
