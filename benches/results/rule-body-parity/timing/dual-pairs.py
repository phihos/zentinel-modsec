from pathlib import Path
from statistics import median
from contextlib import ExitStack
import subprocess,os,json,sys,hashlib
p=Path(__file__).resolve().parent
before,after,tag,rounds=sys.argv[1:];rounds=int(rounds)
keys=[before,after];wls=['get','form','json'];target=p/tag;target.mkdir(exist_ok=True)
meta=[json.loads((p/(k+'.json')).read_text()) for k in keys]
assert meta[0]['benchmark']==meta[1]['benchmark']
for k,m in zip(keys,meta):m['worker_sha256']=hashlib.sha256((p/(k+'.dual')).read_bytes()).hexdigest()
r=dict(workloads=wls,sources=meta,cpu=14,requests_per_batch=96,batches_per_pair=10,runs=[])
def measure(proc,count):
 proc.stdin.write(str(count)+'\n');proc.stdin.flush();return [int(v)/count/1000 for v in proc.stdout.readline().split()]
def close(proc):
 proc.stdin.close();assert proc.wait(timeout=10)==0
for i in range(rounds):
 with ExitStack() as stack:
  procs={}
  for k in keys[::1 if i%2==0 else -1]:
   for w in wls:
    b=subprocess.Popen(['taskset','-c','14',str(p/(k+'.dual')),w],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=None,text=True,env=dict(os.environ,CRS_BENCH_DIR='/tmp/zentinel-pr-crs-4.25.0'))
    assert b.stdout.readline().strip()=='ready '+w
    stack.callback(close,b);procs[k,w]=b; measure(b,150)
  vals={k:{w:[] for w in wls} for k in keys}
  for j in range(10):
   for off in range(3):
    w=wls[(off+j+i)%3]
    for k in keys[::1 if (i+j)%2==0 else -1]:
     vals[k][w].append(measure(procs[k,w],96))
  r['runs'].append(vals)
  summary={}
  for w in wls:
   a,b=[[median(pair[0] for pair in v[k][w]) for v in r['runs']] for k in keys]
   summary[w]=dict(before_us=median(a),after_us=median(b),paired_percent=median((y/x-1)*100 for x,y in zip(a,b)),wins=sum(y<x for x,y in zip(a,b)))
  r['cpu_summary']={}
  for w in wls:
   a,b=[[median(pair[1] for pair in v[k][w]) for v in r['runs']] for k in keys]
   r['cpu_summary'][w]=dict(before_us=median(a),after_us=median(b),paired_percent=median((y/x-1)*100 for x,y in zip(a,b)),wins=sum(y<x for x,y in zip(a,b)))
  r['summary']=summary
  print(i,summary,flush=True);(target/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
