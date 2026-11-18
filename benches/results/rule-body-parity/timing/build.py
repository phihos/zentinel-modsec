"""Build the exact integrated engine against the fixed full-CRS PR #69 workload."""
from pathlib import Path
import hashlib,json,os,subprocess,shutil,sys
p=Path(__file__).resolve().parent;w=p/'engine';target=p/'target'
rev=sys.argv[1];lock=Path(sys.argv[2]).resolve()
assert len(rev)==40 and lock.is_file()
def git(*a):return subprocess.check_output(['git','-C',w,*a],text=True).strip()
def h(f):return hashlib.sha256(Path(f).read_bytes()).hexdigest()
def call(*a,**opts):subprocess.run([str(s) for s in a],check=True,**opts)
assert not git('status','--porcelain') and git('rev-parse',rev+'^{commit}')==rev
git('checkout','--detach',rev);assert git('rev-parse','HEAD')==rev
shutil.copyfile(lock,w/'Cargo.lock');shutil.copyfile(lock,p/(rev[:8]+'.lock'))
ref=json.loads((p/'19cc4993.json').read_text())
assert h(p/'full_crs.rs')==ref['benchmark'] and h(p/'resident.rs')==ref['driver_sha256']
env=os.environ|dict(CARGO_TARGET_DIR=str(target),CARGO_BUILD_JOBS='3',CRS_BENCH_DIR='/tmp/zentinel-pr-crs-4.25.0')
crs=Path(env['CRS_BENCH_DIR']);crs_rev=subprocess.check_output(['git','-C',crs,'rev-parse','HEAD'],text=True).strip()
assert crs_rev=='aabf675fcfc5e489b424b844e6c9f1b39802df69' and not subprocess.check_output(['git','-C',crs,'status','--porcelain','--','rules','crs-setup.conf.example'],text=True).strip()
call('cargo','clean','--locked','--offline','--release','-p','zentinel-modsec',cwd=w,env=env)
command=['taskset','-c','1-4','cargo','bench','--locked','--offline','--no-run','--bench','modsec_bench','--message-format=json']
with (p/(rev[:8]+'.build.jsonl')).open('w') as f:call(*command,env=env,cwd=w,stdout=f)
rows=[json.loads(l) for l in (p/(rev[:8]+'.build.jsonl')).read_text().splitlines() if l.startswith('{')]
engine=next(Path(name) for r in rows if r.get('reason')=='compiler-artifact' and r['target']['name']=='zentinel_modsec' for name in r['filenames'] if name.endswith('.rlib'))
exe=p/(rev[:8]+'.dual')
call('taskset','-c','3','rustc','--edition=2021','-C','opt-level=3','-C','debuginfo=0','--extern','zentinel_modsec='+str(engine),'-L','dependency='+str(engine.parent),p/'resident.rs','-o',exe,cwd=w,env=env|dict(FULL_CRS_SOURCE=str(p/'full_crs.rs')))
assert not git('status','--porcelain') and git('rev-parse','HEAD')==rev and h(w/'Cargo.lock')==h(lock)
compiler=subprocess.check_output(['rustc','-Vv'],text=True);assert compiler==ref['compiler']
r=dict(commit=rev,tree=git('rev-parse','HEAD^{tree}'),binary=h(exe),engine_rlib=h(engine),lock=h(lock),benchmark=h(p/'full_crs.rs'),driver_sha256=h(p/'resident.rs'),compiler=compiler,crs=crs_rev)
(p/(rev[:8]+'.json')).write_text(json.dumps(r,indent=2)+'\n')
print(rev,r['binary'],flush=True)
