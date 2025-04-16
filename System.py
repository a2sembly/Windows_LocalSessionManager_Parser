# terminal_services_lsm_parser.py
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import csv
from common import Common

class SystemParser:
    DESC_MAP = {
        #'7036': '서비스 상태 변경',
        '7045': '서비스 설치',
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
                ud = root.find('.//ev:UserData/ud:EventXML', ns)
                hostname = Common.safe_find_text(root, './/ev:System/ev:Computer', ns)
                if evt_id == '7036':
                    evdata = Common.parse_event_data(root, ns)
                    Servicename = evdata.get('param1', '-')
                    Status = evdata.get('param2', '-')
                    details = f"Service: {Servicename}, Status: {Status}"
                elif evt_id == '7045':
                    evdata = Common.parse_event_data(root, ns)
                    Servicename = evdata.get('ServiceName', '-')
                    Path = evdata.get('ImagePath', '-')
                    Type = evdata.get('ServiceType', '-')
                    StartType = evdata.get('StartType','-')
                    details = f"Service: {Servicename}, Path: {Path}, Type: {Type}, StartType: {StartType}"
                    

                writer.writerow([
                    timestamp, 'Logged', hostname or '-', '-',
                    self.DESC_MAP[evt_id], details, '-',
                    self.evtx_path.split('\\')[-1]
                ])
