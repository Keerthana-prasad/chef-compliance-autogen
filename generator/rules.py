"""Rule types for the compliance generator.

Every rule type knows three things:

* how to validate its params - strictly, because params end up inside
  generated Ruby code (a loose validator would allow code injection);
* how to render the InSpec check (the *scan*);
* how to render the Chef Infra resource that fixes it (the *remediation*),
  or ``None`` when the rule is scan-only (e.g. cloud resources).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


class RuleError(ValueError):
    """Raised when a benchmark rule is invalid."""


def rb(value: Any) -> str:
    """Return *value* as a safe single-quoted Ruby string literal."""
    text = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{text}'"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    impact: float
    type: str
    params: dict = field(default_factory=dict)
    rationale: str = ""
    tags: tuple = ()


def _param(rule: Rule, key: str, pattern: str, what: str, default: Any = None) -> str:
    value = rule.params.get(key, default)
    if value is None:
        raise RuleError(f"{rule.id}: missing param '{key}'")
    if isinstance(value, bool):
        # YAML 1.1 turns unquoted yes/no/on/off into booleans.
        raise RuleError(
            f"{rule.id}: param '{key}' parsed as a boolean - quote it in YAML (e.g. \"no\")"
        )
    value = str(value)
    if not re.fullmatch(pattern, value):
        raise RuleError(f"{rule.id}: invalid {what} {value!r} for param '{key}'")
    return value


def _check_known_params(rule: Rule, allowed: set[str]) -> None:
    unknown = set(rule.params) - allowed
    if unknown:
        raise RuleError(f"{rule.id}: unknown params {sorted(unknown)}")


class RuleType:
    name: str = ""
    dependencies: tuple[str, ...] = ()   # InSpec resource packs the check needs
    uses_setting_helpers = False         # recipe needs read_setting/write_setting

    def validate(self, rule: Rule) -> None:
        raise NotImplementedError

    def inputs(self, rule: Rule) -> list[dict]:
        return []

    def inspec(self, rule: Rule) -> str:
        raise NotImplementedError

    def chef(self, rule: Rule) -> str | None:
        return None


class KeyValueSetting(RuleType):
    """A ``Key value`` line in a whitespace-separated config file."""

    uses_setting_helpers = True
    KEY = r"[A-Za-z][A-Za-z0-9_]*"
    VALUE = r"[A-Za-z0-9_.,:/@+-]+"

    def __init__(self, name: str, inspec_resource: str, path: str):
        self.name = name
        self.inspec_resource = inspec_resource
        self.path = path

    def _parts(self, rule: Rule) -> tuple[str, str, str]:
        _check_known_params(rule, {"key", "value", "compare"})
        key = _param(rule, "key", self.KEY, "config key")
        compare = _param(rule, "compare", "eq|max|min", "comparison", default="eq")
        pattern = r"\d+" if compare != "eq" else self.VALUE
        value = _param(rule, "value", pattern, "value")
        return key, value, compare

    def validate(self, rule: Rule) -> None:
        self._parts(rule)

    def inspec(self, rule: Rule) -> str:
        key, value, compare = self._parts(rule)
        matcher = {"eq": rb(value), "max": f"<= {value}", "min": f">= {value}"}[compare]
        return (
            f"describe {self.inspec_resource} do\n"
            f"  its({rb(key)}) {{ should cmp {matcher} }}\n"
            f"end"
        )

    def chef(self, rule: Rule) -> str:
        key, value, compare = self._parts(rule)
        current = f"read_setting.call({rb(self.path)}, {rb(key)}).to_s"
        if compare == "eq":
            guard = f"{current}.casecmp?({rb(value)})"
        else:
            # Only fix values that are actually out of policy, so a stricter
            # existing setting (e.g. 90 days when the limit is 365) is kept.
            op = "<=" if compare == "max" else ">="
            guard = f"(v = {current}).match?(/\\A\\d+\\z/) && v.to_i {op} {value}"
        return (
            f"ruby_block {rb(rule.id + ': ' + rule.title)} do\n"
            f"  block {{ write_setting.call({rb(self.path)}, {rb(key)}, {rb(value)}) }}\n"
            f"  not_if {{ {guard} }}\n"
            f"end"
        )


class FilePermissions(RuleType):
    name = "file_permissions"
    PATH = r"/[A-Za-z0-9_./-]+"
    MODE = r"0[0-7]{3}"
    ACCOUNT = r"[a-z_][a-z0-9_-]*"

    def _parts(self, rule: Rule) -> tuple[str, str, str, str]:
        _check_known_params(rule, {"path", "max_mode", "owner", "group"})
        return (
            _param(rule, "path", self.PATH, "absolute path"),
            _param(rule, "max_mode", self.MODE, "octal mode"),
            _param(rule, "owner", self.ACCOUNT, "user name"),
            _param(rule, "group", self.ACCOUNT, "group name"),
        )

    def validate(self, rule: Rule) -> None:
        self._parts(rule)

    def inspec(self, rule: Rule) -> str:
        path, mode, owner, group = self._parts(rule)
        return (
            f"describe file({rb(path)}) do\n"
            f"  it {{ should exist }}\n"
            f"  it {{ should_not be_more_permissive_than({rb(mode)}) }}\n"
            f"  its('owner') {{ should eq {rb(owner)} }}\n"
            f"  its('group') {{ should eq {rb(group)} }}\n"
            f"end"
        )

    def chef(self, rule: Rule) -> str:
        path, mode, owner, group = self._parts(rule)
        ruby_mode = "0o" + mode[1:]
        return (
            f"file {rb(path)} do\n"
            f"  owner {rb(owner)}\n"
            f"  group {rb(group)}\n"
            f"  mode {rb(mode)}\n"
            f"  only_if {{ ::File.exist?({rb(path)}) }}\n"
            f"  not_if do\n"
            f"    st = ::File.stat({rb(path)})\n"
            f"    (st.mode & 0o7777 & ~{ruby_mode}).zero? &&\n"
            f"      ::Etc.getpwuid(st.uid).name == {rb(owner)} &&\n"
            f"      ::Etc.getgrgid(st.gid).name == {rb(group)}\n"
            f"  end\n"
            f"end"
        )


class PackageAbsent(RuleType):
    name = "package_absent"
    PACKAGE = r"[a-z0-9][a-z0-9.+-]*"

    def _name(self, rule: Rule) -> str:
        _check_known_params(rule, {"name"})
        return _param(rule, "name", self.PACKAGE, "package name")

    def validate(self, rule: Rule) -> None:
        self._name(rule)

    def inspec(self, rule: Rule) -> str:
        return (
            f"describe package({rb(self._name(rule))}) do\n"
            f"  it {{ should_not be_installed }}\n"
            f"end"
        )

    def chef(self, rule: Rule) -> str:
        return f"package {rb(self._name(rule))} do\n  action :remove\nend"


class AwsS3Bucket(RuleType):
    """Scan-only check from the inspec-aws resource pack."""

    name = "aws_s3_bucket"
    dependencies = ("inspec-aws",)
    INPUT = r"[a-z_][a-z0-9_]*"
    BUCKET = r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"
    CHECKS = {
        "not_public": "it { should_not be_public }",
        "default_encryption": "it { should have_default_encryption_enabled }",
        "versioning": "it { should have_versioning_enabled }",
    }

    def _parts(self, rule: Rule) -> tuple[str, str, str]:
        _check_known_params(rule, {"input", "default", "check"})
        return (
            _param(rule, "input", self.INPUT, "input name"),
            _param(rule, "default", self.BUCKET, "bucket name"),
            _param(rule, "check", "|".join(self.CHECKS), "check"),
        )

    def validate(self, rule: Rule) -> None:
        self._parts(rule)

    def inputs(self, rule: Rule) -> list[dict]:
        name, default, _ = self._parts(rule)
        return [{"name": name, "value": default, "description": "S3 bucket to check"}]

    def inspec(self, rule: Rule) -> str:
        name, _, check = self._parts(rule)
        return (
            f"describe aws_s3_bucket(bucket_name: input({rb(name)})) do\n"
            f"  {self.CHECKS[check]}\n"
            f"end"
        )


RULE_TYPES: dict[str, RuleType] = {
    t.name: t
    for t in (
        KeyValueSetting("sshd_option", "sshd_config", "/etc/ssh/sshd_config"),
        KeyValueSetting("login_defs", "login_defs", "/etc/login.defs"),
        FilePermissions(),
        PackageAbsent(),
        AwsS3Bucket(),
    )
}
