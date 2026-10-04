"""Create and clean up an isolated ephemeral Kafka compatibility probe."""
from pathlib import Path
import subprocess, time, socket
ROOT=Path(__file__).resolve().parents[1]
NAME='tracehawk-phase0-kafka'
KAFKA='apache/kafka:4.3.0@sha256:0be4c9eb3565733612d2836d65636fd611a219ebcf5b4162e5ac259ea0ecb907'
PYTHON='python:3.13.16-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed'
def run(args,**kw):return subprocess.run(args,check=True,**kw)
def main():
 with socket.socket() as sock:sock.bind(('127.0.0.1',19092))
 if subprocess.run(['docker','inspect',NAME],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
  raise SystemExit(f'{NAME} already exists; inspect it before rerunning')
 args=['docker','run','-d','--name',NAME,'--label','dev.tracehawk.phase=0','--memory','1g','--cpus','2','-p','127.0.0.1:19092:19092']
 env={'KAFKA_NODE_ID':'1','KAFKA_PROCESS_ROLES':'broker,controller','KAFKA_LISTENERS':'PLAINTEXT://:19092,CONTROLLER://:9093',
      'KAFKA_ADVERTISED_LISTENERS':'PLAINTEXT://127.0.0.1:19092','KAFKA_LISTENER_SECURITY_PROTOCOL_MAP':'CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT',
      'KAFKA_CONTROLLER_LISTENER_NAMES':'CONTROLLER','KAFKA_CONTROLLER_QUORUM_VOTERS':'1@localhost:9093',
      'KAFKA_INTER_BROKER_LISTENER_NAME':'PLAINTEXT','KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR':'1',
      'KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR':'1','KAFKA_TRANSACTION_STATE_LOG_MIN_ISR':'1',
      'KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS':'0','KAFKA_HEAP_OPTS':'-Xms256m -Xmx512m'}
 for k,v in env.items():args.extend(['-e',f'{k}={v}'])
 run(args+[KAFKA],stdout=subprocess.DEVNULL)
 try:
  for _ in range(40):
   r=subprocess.run(['docker','exec',NAME,'/opt/kafka/bin/kafka-topics.sh','--bootstrap-server','localhost:19092','--list'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
   if r.returncode==0:break
   time.sleep(.5)
  else:raise RuntimeError('Kafka readiness timed out')
  for topic in ('phase0-go','phase0-python'):
   run(['docker','exec',NAME,'/opt/kafka/bin/kafka-topics.sh','--bootstrap-server','localhost:19092','--create','--topic',topic,'--partitions','3','--replication-factor','1'],stdout=subprocess.DEVNULL)
  run(['go','run','./cmd/kafka'],cwd=ROOT/'tools/compatibility',timeout=120)
  run(['docker','run','--rm','--network',f'container:{NAME}','--memory','512m','--cpus','1','-v',f'{ROOT}:/work','-w','/work',PYTHON,
       'sh','-c','pip install --disable-pip-version-check --no-cache-dir -q -r contracts/requirements-runtime-probe.txt && python tools/compatibility/python_runtime.py'],timeout=180)
 finally:
  run(['docker','rm','-f',NAME],stdout=subprocess.DEVNULL)
if __name__=='__main__':main()
