# terminal_services_lsm_parser.py
import Evtx.Evtx as evtx
import csv
from common import Common
import xml.etree.ElementTree as ET

class TerminalServicesLSMParser:
    DESC_MAP = {
        '21': '세션 다시 연결 성공',
        '22': '세션 다시 연결 실패',
        '23': '세션 연결 성공',
        '24': '세션 연결 종료',
        '25': '세션 상태 변경'
    }

    def __init__(self, evtx_path: str, csv_path: str):
        self.evtx_path = evtx_path
        self.csv_path = csv_path

    def parse(self):
        with evtx.Evtx(self.evtx_path) as log, open(self.csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Timestamp','Logged','Hostname','ExtIP','Description','Details','-','SourceFile'])

            for record in log.records():
                root = ET.fromstring(record.xml())
                evt_id = Common.safe_find_text(root, './/ev:System/ev:EventID', Common.NS)
                if evt_id not in self.DESC_MAP:
                    continue

                timestamp = Common.parse_timestamp(root)
                ud = root.find('.//ev:UserData/ud:EventXML', Common.NS)
                user      = Common.safe_find_text(ud, 'ud:User', Common.NS)
                addr      = Common.safe_find_text(ud, 'ud:Address', Common.NS)
                sessionid = Common.safe_find_text(ud, 'ud:SessionID', Common.NS)
                extip = addr if Common.is_public_ip(addr) else '-'
                details = f"User: {user}, IP: {addr}, Session ID: {sessionid}"

                writer.writerow([
                    timestamp, 'Logged', '-', extip,
                    self.DESC_MAP[evt_id], details, '-',
                    self.evtx_path.split('\\')[-1]
                ])
