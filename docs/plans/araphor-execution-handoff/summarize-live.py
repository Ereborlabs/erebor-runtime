import sys,pathlib,re,collections,json,time
b=pathlib.Path(sys.argv[1]); log=pathlib.Path(str(b)+'.log')
p=pathlib.Path(str(b)+'-timing.txt'); proc=pathlib.Path(str(b)+'-process.json')
if p.exists(): print(p.read_text().strip())
elif proc.exists(): print('running_s',round(time.monotonic()-json.loads(proc.read_text())['start_monotonic'],6))
lines=log.read_text().splitlines(); packages=collections.defaultdict(list)
for s in lines:
 if 'stage="live_test"' in s: print(s)
 if 'stage="package"' in s:
  key=re.search(r'package_id=([^ ]+)',s)[1]; us=int(re.search(r'elapsed_us=([0-9]+)',s)[1]); packages[key].append(us)
 if 'action="physical_done"' in s and float(re.search(r'elapsed_s=([0-9.]+)',s)[1])>5: print(s)
for label,token in [('failure','Managed subscription execution failed'),('commit','stage="graph_commit"'),('work','stage="source_done"')]:
 selected=[s for s in lines if token in s and (label!='work' or ':evaluate' in s)]
 print(label,'count',len(selected))
 for s in selected[-6:]: print(s)
for k,us in packages.items(): print('package',k,'calls',len(us),'total_ms',sum(us)/1000,'min_ms',min(us)/1000,'max_ms',max(us)/1000)
