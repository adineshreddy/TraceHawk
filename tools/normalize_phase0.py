"""Produce development contract fixtures from actual Zeek logs, not a collector."""
from pathlib import Path
from decimal import Decimal
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]


def micros(value):
    return int((Decimal(str(value))*1000000).to_integral_value())


def main():
    manifest=json.loads((ROOT/'scenarios/phase0/manifest.json').read_text())
    events=[]
    for kind in ('conn','dns'):
        path=ROOT/f'scenarios/phase0/zeek/{kind}.log'
        generation=hashlib.sha256(path.read_bytes()).hexdigest()
        offset=0
        for line in path.read_bytes().splitlines(keepends=True):
            r=json.loads(line,parse_float=Decimal)
            original=micros(r['ts'])
            duration=micros(r['duration']) if 'duration' in r else None
            event_time=original+(duration or 0) if kind=='conn' else original
            identity=['phase0-v1','zeek-offline',generation,kind,offset]
            event={'schema_version':'1.0','event_id':hashlib.sha256(json.dumps(identity,separators=(',',':')).encode()).hexdigest(),
                   'scope_id':'phase0-v1','sensor_id':'zeek-offline','run_id':'phase0-v1',
                   'event_kind':'connection' if kind=='conn' else 'dns','event_time_us':event_time,
                   'original_timestamp_us':original,'ingested_at_us':manifest['time_start_us']+120000000,
                   'published_at_us':manifest['time_start_us']+120001000,
                   'time_basis':('connection_activity_end' if duration is not None else 'original_start_fallback') if kind=='conn' else 'dns_transaction_start',
                   'source_ip':r['id.orig_h'],'destination_ip':r['id.resp_h'],
                   'source_port':r['id.orig_p'],'destination_port':r['id.resp_p'],'protocol':r['proto'],'zeek_uid':r['uid'],
                   'provenance':{'log_kind':kind,'source_generation_id':generation,'record_offset':offset,
                                 'zeek_version':'8.0.10','capture_id':manifest['scenario_id'],'input_mode':'controlled_pcap'},
                   'connection':{'state':r.get('conn_state'),'duration_us':duration,'orig_bytes':r.get('orig_bytes'),
                                 'resp_bytes':r.get('resp_bytes'),'missed_bytes':r.get('missed_bytes')} if kind=='conn' else None,
                   'dns':{'query':r.get('query','').lower().rstrip('.') or None,'rcode':r.get('rcode'),'rcode_name':r.get('rcode_name'),
                          'qtype':r.get('qtype'),'trans_id':r.get('trans_id'),'answers':r.get('answers',[])} if kind=='dns' else None}
            events.append(event)
            offset+=len(line)
    events.sort(key=lambda e:(e['event_time_us'],e['event_id']))
    output=ROOT/'scenarios/phase0/normalized-events.jsonl'
    output.write_text(''.join(json.dumps(e,separators=(',',':'))+'\n' for e in events))
    print(f'Normalized {len(events)} actual Zeek records; fixture ingestion times are explicitly synthetic.')


if __name__=='__main__':main()
