import multiprocessing
from concurrent.futures import ProcessPoolExecutor
import tcpdump
import pickle
import re
from itertools import repeat

@DeprecationWarning
def Inspect_packet_by_patterns(packet, patterns, lastTime=None):
    '''
    주어진 정규식 리스트 각각에 주어진 패킷을 대입해보고, 가장 처음으로 매칭된 정규식과 함께 반환한다.
    반환 타입: (패킷 시각정보, 정규식, 매칭패턴, 페이로드)
    '''
    payload = packet[-1]
    if lastTime is None:
        print("checking for", packet[0])
    else:
        print("checking for", packet[0], "last packet:", lastTime)

    for regexEngn in patterns:
        cand = regexEngn.search(payload)
        if cand:
            return (packet[0], regexEngn.pattern, cand.group(), payload)
    return None

class _Inspector():
    '''
    파이썬의 멀티프로세싱 모듈을 사용하기 위해선 전역으로 선언된 객체를 이용해야 한다.
    따라서 클래스를 이용하여 nested function을 구현하였다.
    '''
    def __init__(self, pattern):
        self.pattern = pattern
        return
    def __call__(self, payload):
        if self.pattern.search(payload):
            return payload
        else:
            return None

def Inspect_packets(pattern, packets):
    '''
    하나의 정규식과 여러 패킷이 들어왔을 때, 정규식에 매칭되는 모든 패킷들을 반환한다.
    반환 형식은 배칭된 패킷들의 리스트이다.
    '''

    payloads = (packet[-1] for packet in packets)
    pool = ProcessPoolExecutor()
    return [payload for payload in pool.map(_Inspector(pattern), payloads) if payload is not None]
    
def ExtractRules(snort_rule_path):
    '''
    인자: snort_rule 파일 경로
    정규식을 추출해 리스트로 반환한다.
    '''
    f = open(snort_rule_path)
    lines = f.readlines()
    regexEngn = re.compile(r'(?<=pcre:").*?(?="[;,])')

    ret = [pattern.group() for pattern in map(regexEngn.search, lines) if pattern]
    f.close()
    return ret

if __name__ == "__main__":
    from sys import argv
    rules = ExtractRules(argv[1])
    patterns = (re.compile(rule) for rule in rules)
    packets = tcpdump.Deserialize(argv[2])
    for pattern in patterns:
        print(Inspect_packets(pattern, packets))