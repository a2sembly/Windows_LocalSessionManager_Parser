# terminal_services_lsm_parser.py
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import csv
from common import Common

class TerminalServicesLSMParser:
    DESC_MAP = {
        '21': '세션 로그온 성공',
        '22': '셀 시작 알림',
        '23': '세션 로그오프프',
        '24': '세션 연결 끊김',
        '25': '세션 다시 연결 성공',
        '39': '세션(RDP) 사용자 연결 종료 (39)',
        '40': '세션(RDP) 사용자 연결 종료 (40)'
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

                timestamp = Common.parse_timestamp(root, ns)
                ud = root.find('.//ev:UserData/ud:EventXML', ns)
                user = addr = sessionid = extip = details = sourceid = reasoncode = ""
                if evt_id in ['21','22','23','24','25']:
                    user      = Common.safe_find_text(ud, 'ud:User', ns)
                    addr      = Common.safe_find_text(ud, 'ud:Address', ns)
                    sessionid = Common.safe_find_text(ud, 'ud:SessionID', ns)
                    extip = addr if Common.is_public_ip(addr) else '-'
                    details = f"User: {user}, IP: {addr}, Session ID: {sessionid}"
                elif evt_id == '39':
                    sessionid = Common.safe_find_text(ud, 'ud:TargetSession', ns)
                    sourceid = Common.safe_find_text(ud, 'ud:Source', ns)
                    details = f"Session {sessionid} has been disconnected by session {sourceid}"
                else:
                    sessionid = Common.safe_find_text(ud, 'ud:Session', ns)
                    reasoncode = Common.safe_find_text(ud, 'ud:Reason', ns)
                    details = f"Session {sessionid} has been disconnected, reason code {reasoncode}"
                    

                writer.writerow([
                    timestamp, 'Logged', '-', extip,
                    self.DESC_MAP[evt_id], details, '-',
                    self.evtx_path.split('\\')[-1]
                ])
