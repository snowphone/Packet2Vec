import Snort
import Parser
import Inspect
import sys
import gensim.models.word2vec as w2v

def ExtractPayload(packets):
    return [packet[-1] for packet in packets]

def SplitPayload(payload, length=20, pattern=None):
    '''
    payload를 length 단위로 잘라 string list로 반환한다.
    regexEngn이 인자로 들어온 경우 일치한 패턴을 중심으로 length 단위로 자른다.
    '''
    if pattern is None:
        return [payload[i:i+length] for i in range(0,len(payload),length)]

    idx = payload.find(pattern)
    prePattern = payload[:idx]
    postPattern = payload[idx + len(pattern) :]
    return [word[::-1]  for word in SplitPayload(prePattern[::-1],length)] + [pattern] + SplitPayload(postPattern,length)

def main():
    '''
    학습에 초점
    '''
    sys.argv = [None, "outside.tcpdump_fri.ascii_out.ser_malware", "inside.tcpdump_fri.ascii_out.ser_malware"]

    #get malware packets
    for path in sys.argv[2:]:
        malware_packets = Parser.Deserialize(path)
        malware_payloads = ExtractPayload(malware_packets)
        matched_string = [[packet[2]] for packet in malware_packets]

    length = 40
    trainData = [SplitPayload(payload, length,regexEngn) for time,rule,regexEngn,payload in malware_packets]

    model = w2v.Word2Vec(sentences=trainData,min_count=0)

    packets = Parser.Deserialize(sys.argv[1])
    sentences = [packet[-1] for packet in packets]

    for time, rule, matched, payload in packets:
        print(model.most_similar(positive=[matched]))

    return

if __name__ == "__main__":
    main()