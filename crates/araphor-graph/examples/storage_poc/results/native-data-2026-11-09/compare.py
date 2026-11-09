import hashlib,json,pathlib,statistics,subprocess,time
root=pathlib.Path.cwd()
out=root/'output/araphor-fjall-migration-20261109'
old=out/'native-graph-poc'
new=out/'native-data-poc'
records=[]
for pair,order in enumerate([('before','after'),('after','before'),('after','before'),('before','after')]):
 for label in order:
  binary=old if label=='before' else new
  report=out/f'native-data-pair-{pair}-{label}.json'
  cmd=['rtk','proxy',str(binary),str(report),'combined']
  start=time.time()
  with open(out/f'native-data-pair-{pair}-{label}.log','w') as log:
   process=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
  record={'pair':pair,'label':label,'command':cmd,'start':start,'wall_s':time.time()-start,'exit_code':process.returncode,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
  records.append(record)
  (out/'native-data-pairs.json').write_text(json.dumps(records,indent=2))
  if process.returncode: raise SystemExit(process.returncode)
  subprocess.run(['rtk','proxy','python3','crates/araphor-graph/examples/storage_poc/summarize_cdc.py',str(report)],stdout=open(report.with_name(report.stem+'-summary.json'),'w'),check=True)
summary={"p95_method": 'statistics.quantiles(n=100, method="inclusive"); linear interpolation'}
for label in ['before','after']:
 selected=[]
 for record in records:
  if record['label']==label:
   report=json.loads(pathlib.Path(record['command'][-2]).read_text())
   for run in report['runs']:
    if run['engine']=='fjall-stable': selected.extend(sample for sample in run['samples'] if not sample['restarted'])
 summary[label]={'ordinary_samples':len(selected),'fields_ms':{field:{'median':statistics.median(row[field] for row in selected)*1000,'p95':statistics.quantiles([row[field]*1000 for row in selected],n=100,method='inclusive')[94],'max':max(row[field] for row in selected)*1000} for field in ['total_s','package_s','output_commit_s','output_stage_s','output_sync_s','result_read_s','source_wake_s']}}
(out/'native-data-pair-summary.json').write_text(json.dumps(summary,indent=2))
print(json.dumps(summary,indent=2))
