"""Replay the rule/body fixtures against any clean engine checkout and Coraza v3.8.1."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

fixtures = Path(__file__).resolve().parent
cli = argparse.ArgumentParser()
cli.add_argument("engine", type=Path)
cli.add_argument("output", type=Path)
args = cli.parse_args()
checkout = args.engine.resolve()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=False)

def run(command, cwd, **kwargs):
    return subprocess.run(command, cwd=cwd, text=True, check=True, stdout=subprocess.PIPE, **kwargs).stdout

def git(*arguments):
    return run(["git", *arguments], checkout).strip()

commit = git("rev-parse", "HEAD")
assert not git("status", "--porcelain", "--untracked-files=no")
environment = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0")
build = run(["cargo", "build", "--locked", "--lib", "--message-format=json"], checkout, env=environment)
artifacts = [json.loads(line) for line in build.splitlines()]
libs = {}
for crate in ("zentinel_modsec", "serde_json", "tempfile", "url"):
    libs[crate] = next(Path(f) for row in artifacts if row.get("reason") == "compiler-artifact"
                       and row["target"]["name"] == crate for f in row["filenames"] if f.endswith(".rlib"))
def reference(source, *params):
    return run(["go", "run", "-mod=readonly", str(fixtures/source), *params], fixtures)
def candidate(source, *params, data=None, env=None):
    executable = out/source.split("/")[0]
    command = ["rustc", "--edition=2021", str(fixtures/source), "-o", str(executable)]
    for crate, lib in libs.items():
        command.extend(["--extern", f"{crate}={lib}", "-L", f"dependency={lib.parent}"])
    run(command, checkout)
    return run([executable, *params], checkout, input=data, env=env)

checks = {}
def save(name, go, rust):
    (out/(name+"-go.txt")).write_text(go)
    (out/(name+"-rust.txt")).write_text(rust)

with tempfile.TemporaryDirectory() as temporary:
    scratch = Path(temporary)
    go = reference("body-limits/zentinel-body-ctl-reference.go")
    rust = candidate("body-limits/compare.rs")
    save("body", go, rust)
    assert go == rust and len(rust.splitlines()) == 48
    checks["body_limits"] = 48

    if Path("/proc/self/fd").is_dir():
        spool = scratch/"spool"
        spool.mkdir()
        isolated = dict(os.environ,TMPDIR=str(spool))
        go_exe = scratch/"go-spool"
        run(["go","build","-mod=readonly","-o",go_exe,fixtures/"spooling/reference.go"],fixtures)
        go = run([go_exe],fixtures,env=isolated)
        rust = candidate("spooling/candidate.rs",env=isolated)
        save("spooling",go,rust)
        assert go == rust == "consumed=3 file=false\nconsumed=2 file=true\nconsumed=3 file=true\nphase2=1\nclosed=true\n"
        checks["acquisition_spool_transitions"] = 5

    go = reference("schema/reference.go", scratch/"schema-cases.jsonl")
    rust = candidate("schema/native.rs", scratch/"schema-cases.jsonl", scratch)
    save("schema", go, rust)
    assert go == rust and len(rust.splitlines()) == 22
    checks["schema"] = 22

    cases = fixtures/"recursive/cases.jsonl"
    go = reference("recursive/reference.go", cases)
    rust = candidate("recursive/candidate.rs", cases, scratch)
    save("recursive", go, rust)
    expected = {k: violation for k, _, _, violation in map(json.loads, cases.read_text().splitlines())}
    def decisions(lines):
        return {k: v == "true" for k, v in (line.split() for line in lines.splitlines())}
    pinned = decisions(go)
    native = decisions(rust)
    assert expected == native
    assert {k for k in expected if not k.endswith("boundary")} == set(pinned)
    assert all(native[k] == v for k, v in pinned.items())
    checks.update(recursive_reference=len(pinned), recursive_with_rust_boundaries=len(expected))

    cases = fixtures/"extra/fixtures.json"
    go = reference("extra/reference.go", cases)
    rust = candidate("extra/rust/src/main.rs", cases)
    save("processor", go, rust)
    official = json.loads(go)
    actual = json.loads(rust)
    assert len(actual) == len(official) == 17
    differences = [(a["name"], k, v, b[k]) for a,b in zip(official, actual, strict=True) for k,v in a.items() if v != b[k]]
    assert differences == [("upload-metadata","Files",["410042","43"],[])]
    checks.update(processor_rule_decisions=17, processor_complete_records_equal=16)

    edits = (fixtures/"action-updates/edits.txt").read_text()
    go = reference("action-updates/reference.go")
    rust = candidate("action-updates/candidate.rs", data=edits)
    save("action", go, rust)
    def normalize(line):
        return line.split(" LOAD ERROR")[0] + " LOAD ERROR" if " LOAD ERROR" in line else line
    differences = [(a,b) for a,b in zip(map(normalize,go.splitlines()),rust.splitlines(),strict=True) if a!=b]
    assert len(differences) == 1 and all(line.startswith("11-12 status:-1 ") for line in differences[0])
    checks.update(action_load_and_execution_cases=len(rust.splitlines()), action_equal=len(rust.splitlines())-1)
assert commit == git("rev-parse","HEAD") and not git("status","--porcelain","--untracked-files=no")
receipt = {"engine":commit, "tree":git("rev-parse","HEAD^{tree}"),"coraza":"v3.8.1","checks":checks,
           "engine_lib_sha256":hashlib.sha256(libs["zentinel_modsec"].read_bytes()).hexdigest(),
           "outputs":{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(out.glob("*.txt"))}}
(out/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
print(json.dumps(checks))
