import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import csv
import re
from common import Common

class PowerShellParser:
    DESC_MAP = {
        '400': 'PowerShell 명령 실행'
    }

    def __init__(self, evtx_path: str, csv_path: str):
        self.evtx_path = evtx_path
        self.csv_path = csv_path

    def extract_command_line(self, text: str) -> str:
        """
        HostApplication= 과 EngineVersion= 사이의 문자열 추출
        """
        match = re.search(r"HostApplication=((.|\n)*?)EngineVersion", text)
        return match.group(1).strip() if match else '-'

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
                hostname = Common.safe_find_text(root, './/ev:System/ev:Computer', ns)

                # EventData 전체 추출
                evdata = Common.parse_event_data(root, ns)
                evdata_str = '; '.join(f"{k}={v}" for k, v in evdata.items()) or '-'

                # 마지막 <Data>에서 명령문 추출
                data_nodes = root.findall('.//ev:EventData/ev:Data', ns)
                command_detail = '-'
                if data_nodes:
                    raw_text = data_nodes[-1].text.strip() if data_nodes[-1].text else ''
                    command_detail = self.extract_command_line(raw_text)

                writer.writerow([
                    timestamp,
                    'Logged',
                    hostname or '-',
                    '-',  # extip는 없음
                    self.DESC_MAP[evt_id],
                    command_detail,
                    '-',
                    self.evtx_path.split('\\')[-1]
                ])
