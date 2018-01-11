import Snort
import Parser
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
    인자: 검사용 페이로드, 학습용 페이로드
    '''
    if len(sys.argv) < 2:
        print("No arguments")
        return 

    #get malware packets
    for path in sys.argv[2:]:
        malware_packets = Parser.Deserialize(path)
        malware_payloads = ExtractPayload(malware_packets)
        matched_string = [[packet[2]] for packet in malware_packets]

    wordLength = 10
    trainData = [SplitPayload(payload, wordLength, matchPattern)
                 for time, rule, matchPattern, payload in malware_packets]

    model = w2v.Word2Vec(sentences=trainData,min_count=1)

    testPackets = Parser.Deserialize(sys.argv[1])
    testWordsList = [SplitPayload(payload, wordLength, matchPattern)
                     for time, rule, matchPattern, payload in testPackets]

    matchPatterns = [packet[2] for packet in testPackets]
    for words, pattern in zip(testWordsList, matchPatterns):
        try:
            dsnt_match = model.wv.doesnt_match(words)
            if dsnt_match == pattern:
                print("오탐")
            else:
                print("Doesn't match:", dsnt_match, "Pattern:", pattern)
        except KeyError as e:
            print(e)
    return

if __name__ == "__main__":
    main()
