from pathlib import Path
import json,statistics as st,hashlib
root=Path(__file__).resolve().parent
names=['pairs','repeat']
sets=[json.loads((root/name/'receipt.json').read_text()) for name in names]
sums=[json.loads((root/name/'summary.json').read_text()) for name in names]
assert sums[0]['cpu'] not in sums[1]['logical_siblings']
assert all(len(r['runs'])==8 and r['sources']==sets[0]['sources'] for r in sets)
pair_results={};calls=0
for w in sets[0]['workloads']:
 pair_results[w]={}
 for n,i in [('wall',0),('thread_cpu',1)]:
  pairs=[]
  for run in sets:
   for pair in run['runs']:
    rows=[[v[i] for v in pair[k][w]] for k in (sums[0]['baseline'][:8],sums[0]['candidate'][:8])]
    assert all(len(arm)==10 for arm in rows)
    a,b=map(st.median,rows)
    pairs.append((a,b))
  d=[100*(b/a-1) for a,b in pairs]
  pair_results[w][n]={'baseline_us':st.median(a for a,b in pairs),'candidate_us':st.median(b for a,b in pairs),'median_paired_percent':st.median(d),'wins':sum(x<0 for x in d),'paired_percent':d}
t={'baseline':sums[0]['baseline'],'candidate':sums[0]['candidate'],'pairs_per_workload':16,'measured_requests_per_workload_per_revision':16*10*96,'combined':pair_results,'receipts':{n:hashlib.sha256((root/n/'receipt.json').read_bytes()).hexdigest() for n in names},'per_core':sums}
(root/'comparison.json').write_text(json.dumps(t,indent=2)+'\n')
for w,v in pair_results.items():
 print(w,[(k,round(r['baseline_us'],2),round(r['candidate_us'],2),round(r['median_paired_percent'],2),r['wins']) for k,r in v.items()])
