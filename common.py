# common.py
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime

class Common:
    """
    공통 유틸리티 클래스
    - 동적 네임스페이스 추출
    - IP 유효성 및 공인 IP 판별
    - XML-safe 텍스트 추출
    - TimeCreated 시간 파싱
    """

    @staticmethod
    def get_namespaces(root: ET.Element) -> dict:
        """
        XML 루트로부터 기본(ev) 및 사용자 데이터(ud) 네임스페이스 URI를 추출
        """
        # 기본 네임스페이스 (ev)
        tag = root.tag
        ev_ns = tag[tag.find("{")+1:tag.find("}")] if "}" in tag else ""
        # UserData/EventXML 네임스페이스 (ud)
        ud_elem = root.find('.//{*}EventXML')
        if ud_elem is not None and '}' in ud_elem.tag:
            ud_ns = ud_elem.tag[ud_elem.tag.find("{")+1:ud_elem.tag.find("}")]
        else:
            ud_ns = ""
        return { 'ev': ev_ns, 'ud': ud_ns }

    @staticmethod
    def safe_find_text(element: ET.Element, path: str, ns: dict) -> str:
        """
        주어진 요소에서 path에 맞는 텍스트를 검색, 없으면 '-'
        path는 접두사(ev, ud)를 사용
        """
        if element is None:
            return '-'
        node = element.find(path, ns)
        return node.text if node is not None and node.text else '-'

    @staticmethod
    def parse_timestamp(root: ET.Element, ns: dict) -> str:
        """
        TimeCreated/SystemTime 값을 'YYYY-MM-DD HH:MM:SS' 포맷으로 반환
        """
        tc = root.find('.//ev:System/ev:TimeCreated', ns)
        if tc is not None:
            sts = tc.get('SystemTime', '')
            base = sts.split('.')[0]
            try:
                dt = datetime.strptime(base, '%Y-%m-%dT%H:%M:%S')
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                return base.replace('T', ' ')
        return '-'
    
    @staticmethod
    def is_ip(addr: str) -> bool:
        """
        문자열이 유효한 IPv4 또는 IPv6 주소인지 판단
        """
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_public_ip(addr: str) -> bool:
        """
        주소 문자열이 공인 IP인지 판단
        """
        try:
            ip = ipaddress.ip_address(addr)
            return not (ip.is_private or ip.is_loopback or ip.is_reserved)
        except Exception:
            return False
        
    @staticmethod
    def parse_event_data(root: ET.Element, ns: dict) -> dict:
        """
        <EventData> 안의 <Data Name="..."> 요소를 모두 파싱하여 dict 반환
        """
        data_dict = {}
        ed = root.find('.//ev:System/ev:EventData', ns) or root.find('.//ev:EventData', ns)
        if ed is not None:
            for d in ed.findall('ev:Data', ns):
                name = d.get('Name', '').strip() or '-'
                val = d.text.strip() if d.text else '-'
                data_dict[name] = val
        return data_dict
