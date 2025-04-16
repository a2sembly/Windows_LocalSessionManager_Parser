# main.py
import argparse
from terminal_services_lsm_parser import TerminalServicesLSMParser

PARSERS = {
    'ts_lsm': TerminalServicesLSMParser,
    # 다른 이벤트 파서는 여기에 추가
}


def main():
    parser = argparse.ArgumentParser(description='EVTX 파서 메인')
    parser.add_argument('--type', required=True, choices=PARSERS.keys(), help='파서 타입 선택')
    parser.add_argument('--input', required=True, help='EVTX 파일 경로')
    parser.add_argument('--output', required=True, help='저장할 CSV 경로')
    args = parser.parse_args()

    cls = PARSERS[args.type]
    p = cls(args.input, args.output)
    p.parse()
    print(f"[{args.type}] 파싱 완료: {args.output}")

if __name__ == '__main__':
    main()
