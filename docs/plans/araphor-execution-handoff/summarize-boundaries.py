import pathlib,re,sys
path=pathlib.Path(sys.argv[1]+'.log')
lines=path.read_text().splitlines()
for stage,fields in [
 ('managed_commit_timing',['cut_revision','publication_revision','freeze_s','writer_acquire_s','writer_wait_s','transaction_work_s','commit_s','postcommit_s','elapsed_s']),
 ('graph_conversion',['cut_revision','calls','elapsed_s']),
 ('port_timing',['cut_revision','role','read_id','image','driver_s','header_s','callback_s','binding_s','elapsed_s']),
 ('Notification batch ends',['rows','routed_items','handled_states','decode_s','heads_s','processing_s','elapsed_s'])]:
 selected=[line for line in lines if ('stage="'+stage+'"' in line if stage!='Notification batch ends' else stage in line)]
 print(stage,'count',len(selected))
 def number(line,name):
  m=re.search(r'(?:^| )'+name+r'=([^ ]+)',line)
  return float(m[1]) if m else -1
 worst=sorted(selected,key=lambda line:number(line,'elapsed_s'),reverse=True)[:5]
 shown=selected[:3]+[line for line in worst if line not in selected[:3]]
 for line in shown:
  out=[]
  for name in fields:
   m=re.search(r'(?:^| )'+name+r'=([^ ]+)',line)
   if m:out.append(name+'='+m[1])
  print(line.split(' ',1)[0],*out)
 print('Aggregate work only; concurrent entries do not sum to elapsed wall time.')
