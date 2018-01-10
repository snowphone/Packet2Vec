def Serialize(path, value):
    with open(path,mode="wb+") as output:
        pickle.dump(value, output)
    return

def Search(packets, patterns):
    '''
    snort_rule에 걸리는 패킷을 모아 (패킷 시각, 정규식, 일치한 패턴, 페이로드)를 리스트에 모아 반환한다.
    '''
    log = [(packet[0], regexEngn.pattern, regexEngn.search(packet[-1]).group(), packet[-1])
    for packet in packets
    for regexEngn in patterns
    if print("checking for", packet[0], ", last packet:", packets[-1][0]) or regexEngn.search(packet[-1])]

    return log