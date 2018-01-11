import multiprocessing
import Tcpdump
import pickle
import re

def __examine_packet__(packet, patterns, lastTime):
    '''
    한 패킷에 대해 모든 정규식 검사를 진행한다.
    '''
    payload = packet[-1]
    print("checking for", packet[0], "last packet:", lastTime)
    for regexEngn in patterns:
        cand = regexEngn.search(payload)
        if cand:
            return (packet[0], regexEngn.pattern, cand.group(), payload)
    return None

def Inspect(packets, patterns):
    '''
    입력된 패킷들에 대하여 
    snort_rule에 걸리는 패킷을 모아 (패킷 시각, 정규식, 일치한 패턴, 페이로드)를 리스트에 모아 반환한다.
    '''

    pool = multiprocessing.Pool()  #worker의 수를 자동으로 선택

    records = ((packet, patterns, packets[-1][0]) for packet in packets) 
    malware_packet = [tpl for tpl in pool.starmap(__examine_packet__, records) if tpl ] 

    return malware_packet

def ExtractRule(snort_rule_path):
    f = open(snort_rule_path)
    lines = f.readlines()
    regexEngn = re.compile(r'(?<=pcre:").*?(?="[;,])')

    return [pattern.group() for pattern in map(regexEngn.search, lines) if pattern]