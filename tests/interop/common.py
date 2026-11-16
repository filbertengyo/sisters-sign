"""Shared helpers for the interop test: running sister-sign, keyid, openssl CLI, result table."""

import hashlib
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization


class CaseFailed(Exception):
    """Raised inside a case when an expectation does not hold."""


def expect(cond, message):
    if not cond:
        raise CaseFailed(message)


@dataclass
class Tool:
    """Runs the sister-sign binary inside a work directory (stdin closed, like the e2e harness)."""

    binary: Path
    workdir: Path

    def run(self, *args):
        proc = subprocess.run(
            [str(self.binary), *args],
            cwd=self.workdir,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def must(self, *args):
        rc, out, err = self.run(*args)
        if rc != 0:
            raise CaseFailed(f"sister-sign {' '.join(args)} -> exit {rc}: {err.strip()}")
        return out


def keyid_of(public_key):
    """keyid = hex(SHA-256(DER SPKI)), computed independently of sister-sign."""
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def private_pem(private_key):
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_pem(public_key):
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def parse_field(stdout, name):
    """Value of a `name: value` line printed by keygen/sign."""
    for line in stdout.splitlines():
        if line.startswith(name + ": "):
            return line[len(name) + 2 :]
    raise CaseFailed(f"output has no '{name}:' line")


OPENSSL = shutil.which("openssl")


def openssl_verify(workdir, args):
    """Run an openssl verification command. None = openssl not installed."""
    if OPENSSL is None:
        return None
    proc = subprocess.run(
        [OPENSSL, *args], cwd=workdir, stdin=subprocess.DEVNULL, capture_output=True, text=True
    )
    return proc.returncode == 0


@dataclass
class Results:
    rows: list = field(default_factory=list)

    def run(self, algorithm, direction, case, fn):
        try:
            detail = fn() or ""
            status = "PASS"
        except CaseFailed as e:
            status, detail = "FAIL", str(e)
        except Exception as e:  # unexpected error is a failure, not a crash of the whole run
            status, detail = "FAIL", f"{type(e).__name__}: {e}"
        self.rows.append((algorithm, direction, case, status, detail))
        print(f"  [{status}] {direction}: {case}" + (f" ({detail})" if detail else ""))

    @property
    def failed(self):
        return [r for r in self.rows if r[3] != "PASS"]

    def markdown(self):
        lines = [
            "| Algorithm | Direction | Case | Result | Detail |",
            "|---|---|---|---|---|",
        ]
        for algorithm, direction, case, status, detail in self.rows:
            detail = detail.replace("|", "\\|")
            lines.append(f"| {algorithm} | {direction} | {case} | {status} | {detail} |")
        passed = len(self.rows) - len(self.failed)
        lines.append("")
        lines.append(f"{passed}/{len(self.rows)} cases passed.")
        return "\n".join(lines) + "\n"
