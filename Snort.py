def __serialize__(path):
    with open(path,mode="wb+") as output:
        pickle.dump(log, output)
    return

def Search(path, packets, patterns):
    '''
    snort_rule에 걸리는 패킷을 모아 (패킷 시각, 정규식, 일치한 패턴, 페이로드)를 직렬화해 저장한다.
    '''
    for packet in packets:
        print("checking for", packet[0], ", last packet:", packets[-1][0])
        payload = packet[-1]
        for regexEngn in patterns:
            malware_payload = regexEngn.search(payload)
            if not malware_payload:
                continue
            log.append((packet[0], regexEngn.pattern, malware_payload.group(0), payload))
            print("---Pattern matched---")
            break
    __serialize__(path)
    return