import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import csv
from common import Common

class SecurityParser:
    """
    Windows Security 로그 파서 (Event ID 4624/4625 - 로그인 성공/실패)
    """

    DESC_MAP = {
        '4624': '로그온 성공',
        '4625': '로그온 실패',
        '4634': '로그오프',
        '4648': '명시적 로그온'
    }

    ALLOWED_LOGON_TYPES = {'3', '7', '10'}

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

                evdata = Common.parse_event_data(root, ns)
                logon_type = evdata.get('LogonType', '-')
                if logon_type not in self.ALLOWED_LOGON_TYPES:
                    continue

                timestamp = Common.parse_timestamp(root, ns)
                hostname = Common.safe_find_text(root, './/ev:System/ev:Computer', ns)

                username = evdata.get('TargetUserName', '-')
                logon_id = evdata.get('TargetLogonId', '-')
                ip_address = evdata.get('IpAddress', '-') if Common.is_ip(evdata.get('IpAddress', '')) else ''
                process = evdata.get('ProcessName', '-')
                port= evdata.get('IpPort','-')

                details = f"User: {username}, LogonType: {logon_type}, Address: {ip_address}:{port}, LogonID: {logon_id}, Process: {process}"
                evdata_str = '; '.join(f"{k}={v}" for k, v in evdata.items()) or '-'

                writer.writerow([
                    timestamp,
                    'Logged',
                    hostname or '-',
                    ip_address if ip_address else '-',
                    self.DESC_MAP[evt_id],
                    details,
                    evdata_str,
                    self.evtx_path.split('\\')[-1]
                ])
