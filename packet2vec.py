import Snort
from Tcpdump import Serialize, Deserialize
import sys
import gensim.models.word2vec as w2v

def main():
    '''
    인자: 검사용 페이로드, 학습용 페이로드
    '''
    if len(sys.argv) < 2:
        print("No arguments")
        return 

    #get malware packets
    for path in sys.argv[2:]:
        malware_packets = Deserialize(path)
        malware_payloads = ExtractPayload(malware_packets)
        matched_string = [[packet[2]] for packet in malware_packets]

    wordLength = 20
    trainData = [SplitPayload(payload, wordLength, matchPattern)
                 for time, rule, matchPattern, payload in malware_packets]
    windowSize = 5
    model = w2v.Word2Vec(sentences=trainData,window=windowSize)

    testPackets = Deserialize(sys.argv[1])
    testWordsList = [SplitPayload(payload, wordLength, matchPattern)
                     for time, rule, matchPattern, payload in testPackets]

    matchPatterns = [packet[2] for packet in testPackets]
    falseDetection = 0
    for words, pattern in zip(testWordsList, matchPatterns):
        try:
<<<<<<< HEAD
            doesnt_match = model.wv.doesnt_match(words)
            if doesnt_match == pattern:
=======
            idx = words.index(matchPatterns)
            dsnt_match = model.wv.doesnt_match(words[idx-windowSize:idx+windowSize])
            if dsnt_match == pattern:
>>>>>>> 4a0b789c64f0f75e8e02a9b2f925421260639ad2
                print("오탐")
                falseDetection += 1
            else:
                print("Doesn't match:", doesnt_match, "Pattern:", pattern)
        except KeyError as e:
            print(e)
        except ValueError as e:
            print(e)

<<<<<<< HEAD
    print("결과: 총 {}건 테스트 패킷 중 doesn't match를 통해 스노트의 오탐을 {}건 발견함".format(len()))
=======
    print("결과: 총 {}건의 테스트 패킷 중 doesn't match를 통해 snort의 오탐을 {}건 발견함".format(len(testPackets), falseDetection))
>>>>>>> 4a0b789c64f0f75e8e02a9b2f925421260639ad2
    return

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

if __name__ == "__main__":
    main()
