"""Shell command decomposition.

Agents rarely run one clean command. They chain (``a && b | c``), substitute
(``$(cat .env)``) and wrap (``bash -c "..."``). Policy has to see every simple
command that would actually execute, so this module flattens all of those.
It is a static analyser, not a shell: anything it cannot parse is reported so
the policy can escalate it to a human.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field

OPERATORS = {";", "&&", "||", "|", "&", "(", ")", "|&", ";;"}
REDIRECT_OUT = {">", ">>", ">|", "&>", "&>>", ">&"}
REDIRECT_IN = {"<", "<&"}
WRAPPERS = {"env", "nohup", "time", "nice", "command", "builtin", "exec", "timeout", "stdbuf", "xargs"}
SHELLS = {"sh", "bash", "zsh", "dash"}
SUBST = re.compile(r"\$\(([^()]*)\)|`([^`]*)`|<\(([^()]*)\)")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass
class ShellCommand:
    program: str
    args: list[str]
    stdin_from_pipe: bool = False


@dataclass
class ParsedShell:
    commands: list[ShellCommand] = field(default_factory=list)
    write_redirects: list[str] = field(default_factory=list)
    read_redirects: list[str] = field(default_factory=list)
    error: str | None = None


def parse_shell(command: str, depth: int = 0) -> ParsedShell:
    out = ParsedShell()
    if depth > 4:
        out.error = "shell nesting too deep to analyse"
        return out

    # Command substitutions run first; analyse them as commands of their own.
    for m in SUBST.finditer(command):
        inner = next(g for g in m.groups() if g is not None)
        _absorb(out, parse_shell(inner, depth + 1))
    flat = SUBST.sub(" __SUBST__ ", command)

    try:
        lexer = shlex.shlex(flat, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError as e:  # unbalanced quotes etc.
        out.error = f"could not parse shell command: {e}"
        return out

    segment: list[str] = []
    piped = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.isdigit() and i + 1 < len(tokens) and tokens[i + 1] in REDIRECT_OUT | REDIRECT_IN:
            i += 1  # file-descriptor number of "2>" / "2>&1"
            continue
        if tok in REDIRECT_OUT or tok in REDIRECT_IN:
            if i + 1 < len(tokens) and tokens[i + 1] not in OPERATORS:
                target = tokens[i + 1]
                if not (target.startswith("&") or target.isdigit() or target == "-"):  # 2>&1 is a descriptor
                    (out.write_redirects if tok in REDIRECT_OUT else out.read_redirects).append(target)
                i += 2
                continue
        if tok in OPERATORS:
            _emit(out, segment, piped, depth)
            piped = tok in ("|", "|&")
            segment = []
        else:
            segment.append(tok)
        i += 1
    _emit(out, segment, piped, depth)
    return out


def _emit(out: ParsedShell, words: list[str], piped: bool, depth: int) -> None:
    words = [w for w in words if w != "__SUBST__"]
    while words and ASSIGN.match(words[0]):  # FOO=bar cmd
        words = words[1:]
    while words and os.path.basename(words[0]) in WRAPPERS:
        words = words[1:]
        while words and (words[0].startswith("-") or ASSIGN.match(words[0]) or words[0].isdigit()):
            words = words[1:]  # wrapper flags, env assignments, timeout seconds
    if not words:
        return
    prog = os.path.basename(words[0])
    args = words[1:]
    out.commands.append(ShellCommand(prog, args, stdin_from_pipe=piped))
    if prog in SHELLS and "-c" in args:  # bash -c "inner script"
        idx = args.index("-c")
        if idx + 1 < len(args):
            _absorb(out, parse_shell(args[idx + 1], depth + 1))


def _absorb(out: ParsedShell, inner: ParsedShell) -> None:
    out.commands += inner.commands
    out.write_redirects += inner.write_redirects
    out.read_redirects += inner.read_redirects
    out.error = out.error or inner.error
