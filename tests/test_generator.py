import re
import textwrap
from pathlib import Path

import pytest

from generator.generate import (
    BenchmarkError,
    generate_all,
    load_benchmark,
    render_benchmark,
)
from generator.rules import rb

ROOT = Path(__file__).resolve().parents[1]
LINUX = ROOT / "benchmarks" / "linux_baseline.yml"
AWS = ROOT / "benchmarks" / "aws_dr_storage.yml"

HEADER = """
benchmark:
  name: demo
  title: Demo
  version: 0.1.0
  platform: debian
rules:
"""


def bench_file(tmp_path, rules_yaml):
    path = tmp_path / "demo.yml"
    path.write_text(HEADER + textwrap.indent(textwrap.dedent(rules_yaml), "  "))
    return path


# --- the real benchmarks -------------------------------------------------

def test_every_rule_becomes_a_control_and_a_remediation():
    bench = load_benchmark(LINUX)
    files = render_benchmark(bench)
    controls = files["profiles/linux-baseline/controls/generated.rb"]
    recipe = files["cookbooks/linux_baseline_remediation/recipes/default.rb"]

    assert len(re.findall(r"^control '", controls, re.M)) == len(bench.rules)
    for rule in bench.rules:
        assert f"control '{rule.id}' do" in controls
        assert f"# {rule.id} " in recipe


def test_output_is_deterministic():
    bench = load_benchmark(LINUX)
    assert render_benchmark(bench) == render_benchmark(bench)


def test_committed_build_matches_generator(tmp_path):
    """Generated code is committed; fail if someone edited it by hand or
    changed a benchmark without regenerating."""
    expected = generate_all(sorted((ROOT / "benchmarks").glob("*.yml")), tmp_path / "out")
    committed = {
        p.relative_to(ROOT / "build").as_posix(): p.read_text(encoding="utf-8").replace("\r\n", "\n")
        for p in (ROOT / "build").rglob("*")
        if p.is_file()
    }
    assert committed == expected, "build/ is stale - run: python -m generator"


def test_threshold_rules_never_loosen_stricter_settings():
    recipe = render_benchmark(load_benchmark(LINUX))[
        "cookbooks/linux_baseline_remediation/recipes/default.rb"
    ]
    # The guard skips remediation when the current value is already <= 365.
    assert "v.to_i <= 365" in recipe
    assert "v.to_i <= 4" in recipe


def test_scan_only_benchmark_has_profile_inputs_and_dependency_but_no_cookbook():
    files = render_benchmark(load_benchmark(AWS))
    assert not any(k.startswith("cookbooks/") for k in files)
    meta = files["profiles/aws-dr-storage/inspec.yml"]
    assert "inspec-aws" in meta
    assert "name: primary_bucket" in meta
    assert "input('primary_bucket')" in files["profiles/aws-dr-storage/controls/generated.rb"]


# --- validation ----------------------------------------------------------

def test_duplicate_ids_rejected(tmp_path):
    path = bench_file(tmp_path, """
        - {id: pkg-01, title: A, impact: 0.5, type: package_absent, params: {name: telnet}}
        - {id: pkg-01, title: B, impact: 0.5, type: package_absent, params: {name: rsh}}
    """)
    with pytest.raises(BenchmarkError, match="duplicate"):
        load_benchmark(path)


def test_unknown_type_rejected(tmp_path):
    path = bench_file(tmp_path, """
        - {id: x-01, title: A, impact: 0.5, type: registry_key, params: {}}
    """)
    with pytest.raises(BenchmarkError, match="unknown type"):
        load_benchmark(path)


@pytest.mark.parametrize("impact", [1.5, -0.1, "high", True])
def test_bad_impact_rejected(tmp_path, impact):
    path = bench_file(tmp_path, f"""
        - {{id: pkg-01, title: A, impact: {impact}, type: package_absent, params: {{name: telnet}}}}
    """)
    with pytest.raises(BenchmarkError, match="impact"):
        load_benchmark(path)


def test_unquoted_yaml_no_is_caught(tmp_path):
    # YAML 1.1 parses bare `no` as False - a classic config bug.
    path = bench_file(tmp_path, """
        - {id: ssh-01, title: A, impact: 1.0, type: sshd_option,
           params: {key: PermitRootLogin, value: no}}
    """)
    with pytest.raises(BenchmarkError, match="boolean"):
        load_benchmark(path)


def test_code_injection_in_params_rejected(tmp_path):
    path = bench_file(tmp_path, """
        - id: ssh-01
          title: A
          impact: 1.0
          type: sshd_option
          params: {key: "PermitRootLogin') { system('id') }#", value: "no"}
    """)
    with pytest.raises(BenchmarkError, match="invalid config key"):
        load_benchmark(path)


def test_typo_in_rule_field_rejected(tmp_path):
    path = bench_file(tmp_path, """
        - {id: pkg-01, title: A, impact: 0.5, type: package_absent, paramz: {name: telnet}}
    """)
    with pytest.raises(BenchmarkError, match="unknown fields"):
        load_benchmark(path)


def test_ruby_string_escaping():
    assert rb("it's") == r"'it\'s'"
    assert rb("a\\b") == r"'a\\b'"
