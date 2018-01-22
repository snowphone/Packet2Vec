import multiprocessing
import concurrent.futures as futures
import tcpdump
import pickle
import re
from itertools import repeat

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

def Inspect_packets(pattern, packets):
    '''
    하나의 정규식과 여러 패킷이 들어왔을 때, 정규식에 매칭되는 모든 패킷들을 반환한다.
    반환 형식은 배칭된 패킷들의 리스트이다.
    '''

    pool = futures.ThreadPoolExecutor()
    payloads = (packet[-1] for packet in packets)
    search_result= pool.map(lambda payload: pattern.search(payload), payloads)
    return [payload for payload, ret in zip(payloads, search_result) if ret]

def ExtractRule(snort_rule_path):
    f = open(snort_rule_path)
    lines = f.readlines()
    regexEngn = re.compile(r'(?<=pcre:").*?(?="[;,])')

    return [pattern.group() for pattern in map(regexEngn.search, lines) if pattern]