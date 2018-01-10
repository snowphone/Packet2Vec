import multiprocessing
import pickle


def Serialize(path, value):
    with open(path,mode="wb+") as output:
        pickle.dump(value, output)
    return

def __examine__(packet, patterns, lastTime):
    payload = packet[-1]
    print("checking for", packet[0], "last packet:", lastTime)
    for regexEngn in patterns:
        cand = regexEngn.search(payload)
        if cand:
            return True, (packet[0], regexEngn.pattern, cand.group(), payload)
    return False, None

def Search(packets, patterns):
    '''
    snort_rule에 걸리는 패킷을 모아 (패킷 시각, 정규식, 일치한 패턴, 페이로드)를 리스트에 모아 반환한다.
    '''

    pool = multiprocessing.Pool()  #auto detect threads

    records = ((packet, patterns, packets[-1][0]) for packet in packets) 
    log = [tpl for pred, tpl in pool.starmap(__examine__, records) if pred] #pred 를 통해서 filter의 효과를 구현

    return log