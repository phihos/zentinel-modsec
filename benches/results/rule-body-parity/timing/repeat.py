from pathlib import Path
import datetime, hashlib,json,os,platform,subprocess,time,statistics
root=Path(__file__).resolve().parent
keys=["14eb6a03",os.environ["CRS_BENCH_REV"][:8]]
rounds=8
tag="repeat"
out=root/tag
out.mkdir(exist_ok=True)
def h(file): return hashlib.sha256(file.read_bytes()).hexdigest()
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def cpus():
    rows={}
    for line in Path('/proc/stat').read_text().splitlines():
        col=line.split()
        if col[0][3:].isdigit() and col[0].startswith('cpu'):
            v=[int(x) for x in col[1:9]]
            rows[int(col[0][3:])] = (sum(v),v[3]+v[4])
    return rows
def busy(a,b): return {k:round(100*(1-(b[k][1]-a[k][1])/max(1,b[k][0]-a[k][0])),2) for k in a}
def core(k):
    p=Path('/sys/devices/system/cpu')/f'cpu{k}'/'topology/core_id'
    return int(p.read_text())
def load(): return Path('/proc/loadavg').read_text().strip()
metadata=[json.loads((root/(k+'.json')).read_text()) for k in keys]
assert all(metadata[0][f]==metadata[1][f] for f in ['driver_sha256','benchmark','crs','compiler','lock'])
for k,row in zip(keys,metadata):assert h(root/(k+'.dual'))==row['binary']
assert not (out/'receipt.json').exists()
allowed=sorted(os.sched_getaffinity(0)); cores={c:[x for x in allowed if core(x)==c] for c in {core(x) for x in allowed}}
a=cpus();time.sleep(10);start=cpus();pre=busy(a,start)
original_core=core(json.loads((root/"pairs"/"summary.json").read_text())["cpu"])
print("retesting on a different physical core",flush=True)
siblings=min((vs for c,vs in cores.items() if c!=original_core),key=lambda vs:(sum(pre[c] for c in vs)/len(vs),max(pre[c] for c in vs)))
cpu=min(siblings,key=lambda c:pre[c])
cpudir=Path('/sys/devices/system/cpu')/f'cpu{cpu}'/'cpufreq'
record=dict(start_utc=now(),baseline=metadata[0]['commit'],candidate=metadata[1]['commit'],cpu=cpu,governor=(cpudir/'scaling_governor').read_text().strip(),kernel=platform.release(),logical_siblings=siblings,preflight_busy_percent=pre,start_load=load())
print(json.dumps(record),flush=True)
src=root/'dual-pairs.py'
driver=out/'selected-pairs.py'
driver.write_text(src.read_text().replace("p=Path(__file__).resolve().parent","p=Path(__file__).resolve().parent.parent").replace('cpu=14,','cpu='+str(cpu)+',').replace("'taskset','-c','14'", "'taskset','-c','"+str(cpu)+"'"))
with (out/'progress.log').open('w') as f: subprocess.run(['python','-u',driver,*keys,tag,str(rounds)],cwd=root,stdout=f,check=True)
end=cpus()
receipt=json.loads((out/'receipt.json').read_text())
assert len(receipt['runs'])==rounds and receipt['cpu']==cpu and receipt['batches_per_pair']==10
record.update(end_utc=now(),end_load=load(),during_busy_percent=busy(start,end),thread_cpu_us=receipt['cpu_summary'],wall_us=receipt['summary'],harness_sha256=h(driver),receipt_sha256=h(out/'receipt.json'))
record['wall_to_cpu_by_workload']={k:{w:round(statistics.median(wall/cpu for block in receipt['runs'] for wall,cpu in block[k][w]),3) for w in receipt['workloads']} for k in keys}
record['run_count']=rounds
(out/'summary.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
