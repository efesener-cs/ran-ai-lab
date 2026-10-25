"""Incremental, window-closed telemetry adapter. No future measurements enter features."""
import csv
import math
from pathlib import Path
import statistics


def bucket(t):return math.floor(round(float(t)*10,9))


class Tail:
    def __init__(self,path):self.path=Path(path);self.offset=0;self.pending=''
    def lines(self):
        if not self.path.exists():return []
        with self.path.open() as stream:
            stream.seek(self.offset);text=stream.read();self.offset=stream.tell()
        parts=(self.pending+text).split('\n');self.pending=parts.pop()
        return [line.strip() for line in parts if line.strip()]


class Telemetry:
    def __init__(self,raw,run_id,ues):
        self.run_id=run_id;self.ues=ues;self.last_tick=-1
        raw=Path(raw)
        self.tails={key:Tail(raw/name) for key,name in {
            'sinr':'MmWaveSinrTime.txt','phy':'RxPacketTrace.txt','path':'CellIdStats.txt','app':'app_kpi.csv','control':'control_state.csv'}.items()}
        self.sinr={};self.phy={};self.paths={};self.apps={};self.app_header=None;self.control={};self.control_header=None

    def poll(self):
        # app_kpi is flushed only after all UE rows in a closed window are emitted.
        # Read watermark first, then traces; discard trace data after each window's end.
        for line in self.tails['app'].lines():
            values=next(csv.reader([line]))
            if self.app_header is None:self.app_header=values;continue
            if len(values)!=len(self.app_header):raise ValueError('Malformed application watermark row')
            row=dict(zip(self.app_header,values))
            self.apps.setdefault(bucket(row['window_start_s']),{})[int(row['ue_imsi'])]=row
        for line in self.tails['sinr'].lines():
            t,ue,cell,value=line.split()
            self.sinr.setdefault((bucket(t),int(ue),int(cell)),[]).append(float(value))
        for line in self.tails['phy'].lines():
            row=line.split()
            if row[0]=='DL':
                key=(bucket(row[1]),int(row[7]));count,bad=self.phy.get(key,(0,0))
                self.phy[key]=(count+1,bad+int(row[14]))
        for line in self.tails['path'].lines():
            parts=line.split()
            if len(parts)!=4:raise ValueError('Unexpected path trace layout')
            t,ue,cell,_=parts
            self.paths.setdefault(int(ue),[]).append((float(t),int(cell)))
        for line in self.tails['control'].lines():
            values=next(csv.reader([line]))
            if self.control_header is None:self.control_header=values;continue
            row=dict(zip(self.control_header,values))
            tick=round(float(row['decision_time_s'])*10)-1
            self.control[(tick,int(row['ue_imsi']))]=row
        output=[]
        for tick,apps in sorted(self.apps.items()):
            if tick<=self.last_tick or len(apps)!=self.ues:continue
            cells={cell for t,ue,cell in self.sinr if t==tick}
            for ue,row in sorted(apps.items()):
                end=float(row['window_end_s'])
                past=[(t,c) for t,c in self.paths.get(ue,[]) if t<end]
                path=max(past,key=lambda event:event[0])[1] if past else None
                if (tick,ue) in self.control:path=int(self.control[(tick,ue)]['nr_cell_id'])
                for cell in sorted(cells):
                    values=self.sinr.get((tick,ue,cell),[])
                    previous=self.sinr.get((tick-1,ue,cell),[])
                    if not values or not previous:continue
                    mean=statistics.mean(values);last=values[-1]
                    count,bad=self.phy.get((tick,cell),(0,0))
                    corrupt=bad/count if count else float('nan')
                    output.append(dict(run_id=self.run_id,ue=ue,cell=cell,tick=tick,
                        decision_time_s=end,current=mean,warmup=row['is_warmup']=='1',current_path_cell=path,
                        features=[mean,last,statistics.pstdev(values),mean-statistics.mean(previous),
                                  last-mean,float(count),corrupt,float(not count)]))
            self.last_tick=tick
        if self.last_tick>=0:
            # Retain one prior SINR bin for deltas, plus not-yet-closed windows.
            self.sinr={key:values for key,values in self.sinr.items() if key[0]>=self.last_tick}
            self.phy={key:values for key,values in self.phy.items() if key[0]>self.last_tick}
            self.apps={key:values for key,values in self.apps.items() if key>self.last_tick}
            cutoff=(self.last_tick+1)/10
            for ue,events in self.paths.items():
                earlier=[event for event in events if event[0]<cutoff]
                latest=[max(earlier,key=lambda event:event[0])] if earlier else []
                self.paths[ue]=latest+[event for event in events if event[0]>=cutoff]
        return output
