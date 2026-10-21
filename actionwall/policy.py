"""Declarative policy and the static checks for each action kind.

A policy is YAML (see ``DEFAULT_POLICY``). Every check returns a list of
``Finding``s; the guard combines them so the strictest one wins.
"""

from __future__ import annotations

import copy
import fnmatch
import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .actions import Action, Finding, Kind, Verdict
from .shell import ShellCommand, parse_shell

DEFAULT_POLICY: dict = {
    "workspace": ".",
    "shell": {
        "default": "ask",  # programs not in allow_programs
        "allow_programs": [
            "ls", "cat", "head", "tail", "wc", "grep", "rg", "find", "echo", "pwd", "diff", "sort", "uniq",
            "python", "python3", "pytest", "pip", "uv", "node", "npm", "npx", "tsc", "git", "make",
            "mkdir", "touch", "cp", "mv", "sed", "awk", "jq", "tree", "true", "false", "test",
        ],
        "deny_programs": ["sudo", "su", "doas", "mkfs", "shutdown", "reboot", "halt", "crontab", "launchctl",
                          "systemctl", "chsh", "passwd", "visudo"],
        "network_programs": ["curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "scp", "sftp",
                             "rsync", "ssh", "nslookup", "dig", "host", "ping"],
        "interpreters": ["sh", "bash", "zsh", "dash", "fish", "python", "python3", "node", "perl", "ruby", "php"],
        "deny_patterns": [
            r"\brm\s+(-[a-zA-Z]*\s+)*(/|~/?|\$HOME/?)\*?(\s|$)",  # rm -rf / or ~
            r":\(\)\s*\{.*\};\s*:",                              # fork bomb
            r"\bchmod\s+(-R\s+)?[0-7]*777\s+/",                   # world-writable system dirs
            r"\bdd\b.*\bof=/dev/",                                # overwrite a disk
            r">\s*/dev/(sd|disk|nvme)",
            r"\bhistory\s+-c\b",                                  # covering tracks
        ],
        "ask_patterns": [
            r"\bgit\s+push\b",
            r"\bgit\s+reset\s+--hard\b",
            r"\brm\s+-[a-zA-Z]*r",                                # any recursive delete
            r"\b(npm|pip|uv)\s+(publish|upload)\b",
        ],
    },
    "filesystem": {
        "read_deny": ["~/.ssh/*", "~/.aws/*", "~/.gnupg/*", "~/.config/gcloud/*", "~/.netrc", "~/.docker/config.json",
                      "*/.env", "*/.env.*", "*.pem", "*id_rsa*", "*id_ed25519*", "/etc/shadow", "/etc/sudoers"],
        "read_outside_workspace": "ask",
        "write_deny": ["*/.git/hooks/*", "*/.git/config", "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
                       "~/.ssh/*", "*/.github/workflows/*", "*/.actionwall/*"],
        "write_outside_workspace": "deny",
    },
    "network": {
        "allow_domains": ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "github.com",
                          "api.github.com", "raw.githubusercontent.com", "docs.python.org", "*.readthedocs.io"],
        "deny_domains": ["*.ngrok.io", "*.ngrok-free.app", "pastebin.com", "transfer.sh", "webhook.site",
                         "*.requestbin.net", "*.oast.fun", "*.interact.sh", "*.burpcollaborator.net"],
        "default": "deny",
        "private_ips": "ask",  # localhost / RFC1918
        "public_ips": "deny",  # raw IPs dodge domain allowlists
    },
    "tools": {"allow": [], "ask": [], "deny": [], "default": "ask"},
    "limits": {"max_actions": 500, "max_writes": 200, "max_network": 100},
    "taint": {"enabled": True, "min_secret_length": 12},
}

PATHISH = re.compile(r"^(~|\.{1,2})?/|^~$|^\.[A-Za-z0-9_-]|\.[A-Za-z0-9]{1,8}$")
WRITE_PROGRAMS = {"rm", "mv", "cp", "tee", "touch", "chmod", "chown", "ln", "truncate", "mkdir", "rmdir"}
# Only genuinely internal ranges count as private; ipaddress.is_private also covers
# documentation and reserved blocks, which an attacker can route to.
PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]
URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"]+")


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _v(name: str) -> Verdict:
    return Verdict(name)


def host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for p in patterns:
        p = p.lower()
        if p.startswith("*."):
            if host == p[2:] or host.endswith(p[1:]):
                return True
        elif host == p:
            return True
    return False


@dataclass
class Policy:
    data: dict
    workspace: Path

    @classmethod
    def load(cls, path: str | os.PathLike | None = None, workspace: str | os.PathLike | None = None,
             overrides: dict | None = None) -> "Policy":
        data = copy.deepcopy(DEFAULT_POLICY)
        if path:
            data = _merge(data, yaml.safe_load(Path(path).read_text()) or {})
        if overrides:
            data = _merge(data, overrides)
        ws = Path(workspace or data.get("workspace", ".")).expanduser().resolve()
        return cls(data, ws)

    # -- paths ------------------------------------------------------------------
    def resolve(self, path: str) -> Path:
        p = Path(os.path.expanduser(path))
        if not p.is_absolute():
            p = self.workspace / p
        return Path(os.path.realpath(p))  # collapses .. and follows symlinks

    def in_workspace(self, p: Path) -> bool:
        return p == self.workspace or self.workspace in p.parents

    def _glob_hit(self, p: Path, patterns: list[str]) -> str | None:
        s = p.as_posix()
        for pat in patterns:
            pat_x = os.path.expanduser(pat)
            if fnmatch.fnmatch(s, pat_x) or fnmatch.fnmatch(p.name, pat_x):
                return pat
        return None

    def check_read(self, path: str) -> list[Finding]:
        fs = self.data["filesystem"]
        p = self.resolve(path)
        if hit := self._glob_hit(p, fs["read_deny"]):
            return [Finding(Verdict.DENY, "fs.read_deny", f"{path} matches protected pattern {hit}")]
        if not self.in_workspace(p):
            return [Finding(_v(fs["read_outside_workspace"]), "fs.read_outside", f"{p} is outside the workspace")]
        return []

    def check_write(self, path: str) -> list[Finding]:
        fs = self.data["filesystem"]
        p = self.resolve(path)
        if hit := self._glob_hit(p, fs["write_deny"]):
            return [Finding(Verdict.DENY, "fs.write_deny", f"{path} matches protected pattern {hit}")]
        if not self.in_workspace(p):
            return [Finding(_v(fs["write_outside_workspace"]), "fs.write_outside", f"{p} is outside the workspace")]
        return []

    # -- network ----------------------------------------------------------------
    def check_host(self, host: str) -> list[Finding]:
        net = self.data["network"]
        host = host.strip("[]").lower()
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_loopback or ip.is_link_local or any(ip in n for n in PRIVATE_NETS if n.version == ip.version):
                return [Finding(_v(net["private_ips"]), "net.private_ip", f"{host} is a private address")]
            return [Finding(_v(net["public_ips"]), "net.ip_literal", f"raw IP {host} bypasses the domain allowlist")]
        except ValueError:
            pass
        if host == "localhost":
            return [Finding(_v(net["private_ips"]), "net.private_ip", "localhost")]
        if host_matches(host, net["deny_domains"]):
            return [Finding(Verdict.DENY, "net.deny_domain", f"{host} is a known exfiltration endpoint")]
        if host_matches(host, net["allow_domains"]):
            return []
        return [Finding(_v(net["default"]), "net.not_allowlisted", f"{host} is not on the egress allowlist")]

    def check_url(self, url: str) -> list[Finding]:
        parts = urlsplit(url if "://" in url else f"http://{url}")
        if not parts.hostname:
            return [Finding(Verdict.DENY, "net.bad_url", f"cannot parse host from {url!r}")]
        if parts.scheme not in ("http", "https"):
            return [Finding(Verdict.ASK, "net.scheme", f"unusual scheme {parts.scheme}://")]
        return self.check_host(parts.hostname)

    # -- tools ------------------------------------------------------------------
    def check_tool(self, name: str) -> list[Finding]:
        t = self.data["tools"]
        for verdict, key in ((Verdict.DENY, "deny"), (Verdict.ALLOW, "allow"), (Verdict.ASK, "ask")):
            if any(fnmatch.fnmatch(name, pat) for pat in t[key]):
                return [Finding(verdict, f"tools.{key}", f"tool {name} is on the {key} list")]
        return [Finding(_v(t["default"]), "tools.default", f"tool {name} is not listed")]

    # -- shell ------------------------------------------------------------------
    def check_shell(self, command: str) -> list[Finding]:
        sh = self.data["shell"]
        findings: list[Finding] = []
        for pat in sh["deny_patterns"]:
            if re.search(pat, command):
                findings.append(Finding(Verdict.DENY, "shell.deny_pattern", f"matches dangerous pattern /{pat}/"))
        for pat in sh["ask_patterns"]:
            if re.search(pat, command):
                findings.append(Finding(Verdict.ASK, "shell.ask_pattern", f"matches /{pat}/"))

        parsed = parse_shell(command)
        if parsed.error:
            findings.append(Finding(Verdict.ASK, "shell.unparsable", parsed.error))
            return findings
        for url in URL.findall(command):
            findings += self.check_url(url)
        for cmd in parsed.commands:
            findings += self._check_simple(cmd)
        for path in parsed.write_redirects:
            findings += self.check_write(path)
        for path in parsed.read_redirects:
            findings += self.check_read(path)
        return findings

    def _check_simple(self, cmd: ShellCommand) -> list[Finding]:
        sh = self.data["shell"]
        prog, args = cmd.program, cmd.args
        out: list[Finding] = []
        if prog in sh["deny_programs"]:
            out.append(Finding(Verdict.DENY, "shell.deny_program", f"{prog} is not permitted"))
        if prog in sh["interpreters"] and cmd.stdin_from_pipe:
            out.append(Finding(Verdict.DENY, "shell.pipe_to_interpreter",
                               f"piping data into {prog} executes unreviewed code"))
        if prog in sh["interpreters"] and any(a in ("-c", "-e") for a in args) and prog not in ("sh", "bash", "zsh"):
            out.append(Finding(Verdict.ASK, "shell.inline_code", f"{prog} with inline code cannot be inspected"))
        if prog in sh["network_programs"]:
            hosts = _network_hosts(prog, args)
            if not hosts:
                out.append(Finding(Verdict.ASK, "net.unknown_host", f"{prog} target could not be determined"))
            for h in hosts:
                out += self.check_host(h)
        if prog == "git" and args[:1] and args[0] in ("clone", "fetch", "pull", "push", "remote", "submodule"):
            for a in args:
                if m := re.match(r"^[\w.-]+@([\w.-]+):", a):  # git@host:org/repo
                    out += self.check_host(m.group(1))
        if prog in ("pip", "pip3", "uv", "npm"):
            for i, a in enumerate(args):
                if a in ("-i", "--index-url", "--extra-index-url", "--registry") and i + 1 < len(args):
                    out += self.check_url(args[i + 1])

        # "@file" (curl -d @.env) and "name=@file" (curl -F f=@.env) name files too
        candidates = [a.split("=@", 1)[1] if "=@" in a else a.lstrip("@") for a in args]
        paths = [a for a in candidates if a and not a.startswith("-") and PATHISH.search(a) and "://" not in a]
        for a in paths:
            out += [f for f in self.check_read(a) if f.rule == "fs.read_deny"]  # touching secrets is never ok
        if prog in WRITE_PROGRAMS:
            targets = paths[-1:] if prog in ("cp", "ln") else paths
            for a in targets:
                out += self.check_write(a)

        if prog not in sh["allow_programs"] and prog not in sh["network_programs"] and not out:
            out.append(Finding(_v(sh["default"]), "shell.not_allowlisted", f"{prog} is not on the allowlist"))
        return out


def _network_hosts(prog: str, args: list[str]) -> list[str]:
    positional = [a for a in args if not a.startswith("-")]
    hosts: list[str] = []
    for a in positional:
        if "://" in a:
            host = urlsplit(a).hostname
            if host:
                hosts.append(host)
        elif m := re.match(r"^(?:[\w.-]+@)?([\w.-]+\.[a-zA-Z]{2,}|\d+\.\d+\.\d+\.\d+):", a):  # scp/rsync host:path
            hosts.append(m.group(1))
    if hosts:
        return hosts
    if prog in ("nslookup", "dig", "host", "ping", "nc", "ncat", "netcat", "telnet", "ssh", "ftp", "sftp", "socat"):
        for a in positional:
            a = a.split("@")[-1]  # user@host, dig @resolver
            if a == "localhost" or re.match(r"^\d+\.\d+\.\d+\.\d+$", a) or re.match(r"^[\w-]+(\.[\w-]+)+$", a):
                hosts.append(a)
                break
    if prog in ("curl", "wget") and not hosts:
        for a in positional:
            if re.match(r"^[\w-]+(\.[\w-]+)+(/|$)", a):
                hosts.append(a.split("/")[0])
    return hosts
