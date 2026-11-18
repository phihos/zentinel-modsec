"""Compare the library's public API with pinned Coraza and the 10,000-container bound."""
import argparse, json, os, subprocess, tempfile
from pathlib import Path

p = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument("engine", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--report-only", action="store_true")
args = parser.parse_args()
repo = args.engine.resolve()
result = args.output.resolve()
result.mkdir(parents=True, exist_ok=False)
sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
assert not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=repo)
env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG="0", CARGO_INCREMENTAL="0")
build = subprocess.run(["cargo","build","--locked","--offline","--lib","--message-format=json"],cwd=repo,env=env,capture_output=True,text=True)
(result/"build.log").write_text(build.stderr)
build.check_returncode()
artifacts = [json.loads(line) for line in build.stdout.splitlines()]
cmd = ["rustc", "--edition=2021", str(p/"candidate.rs"), "-o", str(result/"candidate")]
for name in ["serde_json","zentinel_modsec"]:
    lib=next(Path(f) for item in artifacts if item.get("reason")=="compiler-artifact" and item["target"]["name"]==name for f in item["filenames"] if f.endswith(".rlib"))
    cmd.extend(["--extern",f"{name}={lib}","-L",f"dependency={lib.parent}"])
subprocess.run(cmd,check=True)
with tempfile.TemporaryDirectory() as tmp:
    run=subprocess.run([str(result/"candidate"),str(p/"cases.jsonl"),tmp],text=True,capture_output=True)
(result/"rust.log").write_text(run.stdout)
(result/"stderr.log").write_text(run.stderr)
run.check_returncode()
rows={label:expect for label,_,_,expect in map(json.loads,(p/"cases.jsonl").read_text().splitlines())}
def read(path):
    return {k:v=="true" for k,v in (line.split() for line in path.read_text().splitlines())}
go=read(p/"go.log")
rust=read(result/"rust.log")
assert set(rows)==set(rust)
assert set(rows)-set(go)=={"array/boundary","array/above-boundary"}
assert all(value==rows[k] for k,value in go.items())
diff={k:{"expected_violation":rows[k],"actual_violation":v} for k,v in rust.items() if v!=rows[k]}
receipt={"engine":sha,"pinned_coraza":"3.8.1","go_cases":len(go),"rust_cases":len(rust),"worker_stack_bytes":1048576,"differences":diff}
(result/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
print(json.dumps(receipt))
if diff and not args.report_only: raise SystemExit(1)
