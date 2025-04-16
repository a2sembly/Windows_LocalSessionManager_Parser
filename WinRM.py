# terminal_services_lsm_parser.py
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import csv
from common import Common

class WinRMParser:
    DESC_MAP = {
        '132': 'WSMan 작업 완료',
        '145': 'WSMan 작업 시작작',
    }

    def __init__(self, evtx_path: str, csv_path: str):
        self.evtx_path = evtx_path
        self.csv_path = csv_path

    def parse(self):
        with evtx.Evtx(self.evtx_path) as log, open(self.csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Timestamp','Logged','Hostname','ExtIP','Description','Details','-','SourceFile'])

            for record in log.records():
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                # 동적 네임스페이스 추출
                ns = Common.get_namespaces(root)

                # 이벤트 ID
                evt_id = Common.safe_find_text(root, './/ev:System/ev:EventID', ns)
                if evt_id not in self.DESC_MAP:
                    continue
                
                details = hostname = ""
                timestamp = Common.parse_timestamp(root, ns)
                hostname = Common.safe_find_text(root, './/ev:System/ev:Computer', ns)
                if evt_id == '132':
                    evdata = Common.parse_event_data(root, ns)
                    operationName = evdata.get('operationName', '-')
                    details = f"WSMan 작업 {operationName}(를) 완료했습니다."
                elif evt_id == '145':
                    evdata = Common.parse_event_data(root, ns)
                    operationName = evdata.get('operationName', '-')
                    resourceUri = evdata.get('resourceUri', '-')
                    details = f"ResourceUri가 {resourceUri}인 WSMan 작업 Enumeration이(가) 시작되었습니다."
                    

                writer.writerow([
                    timestamp, 'Logged', hostname or '-', '-',
                    self.DESC_MAP[evt_id], details, '-',
                    self.evtx_path.split('\\')[-1]
                ])
