# terminal_services_lsm_parser.py
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import csv
from common import Common
# Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx
class TerminalServicesCAXParser:
    DESC_MAP = {
        '1024': 'RDP OutBound 연결 시도 (1024)',
        '1026': 'RDP OutBound 연결 끊김 (1026)'
    }

    def __init__(self, evtx_path: str, csv_path: str):
        self.evtx_path = evtx_path
        self.csv_path = csv_path

    def parse(self):
        with evtx.Evtx(self.evtx_path) as log, open(self.csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                'Timestamp', 'Logged', 'Hostname', 'ExtIP',
                'Description', 'Details', 'EventData', 'SourceFile'
            ])

            for record in log.records():
                root = ET.fromstring(record.xml())
                ns = Common.get_namespaces(root)

                evt_id = Common.safe_find_text(root, './/ev:System/ev:EventID', ns)
                if evt_id not in self.DESC_MAP:
                    continue

                timestamp = Common.parse_timestamp(root, ns)
                ud = root.find('.//ev:UserData/ud:EventXML', ns)
                # EventData 파싱
                evdata = Common.parse_event_data(root, ns)
                name = evdata.get('Name', '-')
                addr = evdata.get('Value', '-')
                ip = addr if Common.is_ip(addr) else '-'
                # details에 Name과 Value만 넣기
                details = f"Name: {name}, Value: {addr}"

                # EventData 전체는 별도 컬럼에 직렬화
                evdata_str = '; '.join(f"{k}={v}" for k, v in evdata.items()) or '-'

                writer.writerow([
                    timestamp,
                    'Logged',
                    '-',
                    ip,
                    self.DESC_MAP[evt_id],
                    details,
                    evdata_str,
                    self.evtx_path.split('\\')[-1]
                ])