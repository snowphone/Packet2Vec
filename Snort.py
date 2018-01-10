import multiprocessing
import pickle


def Serialize(path, value):
    with open(path,mode="wb+") as output:
        pickle.dump(value, output)
    return

def __examine__(record):
    packet, patterns = record
    payload = packet[-1]
    print("checking for", packet[0])
    for regexEngn in patterns:
        cand = regexEngn.search(payload)
        if cand:
            return True, (packet[0], regexEngn.pattern, cand.group(), payload)
    return False, None

def Search(packets, patterns):
    '''
    snort_rule에 걸리는 패킷을 모아 (패킷 시각, 정규식, 일치한 패턴, 페이로드)를 리스트에 모아 반환한다.
    '''

    records = ((packet,patterns) for packet in packets) #packet: 시각, 송신자, 수신자, 페이로드
    p = multiprocessing.Pool()  #auto detect threads
    log = [tpl for pred, tpl in p.map(__examine__, records) if pred]

    return log