import argparse,json,os,subprocess,time,pathlib
parser=argparse.ArgumentParser()
parser.add_argument('mode',choices=['build','run'])
parser.add_argument('base')
a=parser.parse_args()
case='discovery::packages::required::incident::incremental::follows_incremental_sources'
env=os.environ.copy()
if a.mode=='build':
 env.update(CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='6')
 cmd=['cargo','--config','/tmp/araphor-native55-duckdb-override.toml','test','-p','mithril-e2e','--lib',case,'--no-run','--message-format=short']
else:
 env['RUST_LOG']='info,mithril_e2e=debug,araphor_query=debug,araphor_analysis=debug,araphor_data=debug'
 cmd=['target/debug/deps/mithril_e2e-a9e3c78154ebcf6e',case,'--exact','--nocapture','--test-threads=1']
base=pathlib.Path(a.base)
assert not pathlib.Path(str(base)+'.log').exists()
start=time.monotonic()
with open(str(base)+'.log','wb') as log:
 child=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT,env=env,start_new_session=True)
 pathlib.Path(str(base)+'-process.json').write_text(json.dumps({'pid':child.pid,'start_monotonic':start,'case':case,'mode':a.mode,'cmd':cmd}))
 print(json.dumps({'pid':child.pid,'mode':a.mode,'base':str(base)}),flush=True)
 status=child.wait()
elapsed=time.monotonic()-start
result=f'elapsed_s={elapsed:.6f}\nexit={status}\n'
pathlib.Path(str(base)+'-timing.txt').write_text(result)
print(result,end='',flush=True)
raise SystemExit(status if status>=0 else 128-status)
