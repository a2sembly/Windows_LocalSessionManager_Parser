# common.py
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime

class Common:
    NS = {
        'ev': 'http://schemas.microsoft.com/win/2004/08/events/event',
        'ud': 'Event_NS'
    }

    @staticmethod
    def is_public_ip(addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
            return not (ip.is_private or ip.is_loopback or ip.is_reserved)
        except Exception:
            return False

    @staticmethod
    def safe_find_text(element: ET.Element, path: str, ns: dict) -> str:
        node = element.find(path, ns)
        return node.text if node is not None and node.text else '-'

    @staticmethod
    def parse_timestamp(root: ET.Element) -> str:
        tc = root.find('.//ev:System/ev:TimeCreated', Common.NS)
        if tc is not None:
            sts = tc.get('SystemTime', '')
            base = sts.split('.')[0]
            try:
                dt = datetime.strptime(base, '%Y-%m-%dT%H:%M:%S')
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                return base.replace('T', ' ')
        return '-'