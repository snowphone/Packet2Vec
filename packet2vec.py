import snort
import tcpdump
from tcpdump import Serialize, Deserialize
from sys import argv
import gensim.models.doc2vec as d2v
import re


def main():
    rule_path = argv[1]
    packet_path = argv[2]

    rules = snort.ExtractRules(rule_path)

    patterns = map(re.compile, rules)

    packets = Deserialize(packet_path)

    model = Train(patterns, packets)

def Train(patterns, packets):
    '''
    인자: 정규식 엔진 리스트, 패킷 리스트
    정규식 엔진들과 패킷들을 받아
    정규식을 doc ID로, 그 정규식에 걸러진 payload들을 단어로 삼아 학습시킨 Doc2Vec 객체를 반환한다.
    '''
    payloads = (packet[-1] for packet in packets)

    cnt_fn = lambda i : print("\r{}".format(i), end="")

    #리스트 내의 원소: (걸러진 패이로드들, 정규식)
    mal_records = [(snort.Inspect_packets(pattern,packets), pattern.pattern) for idx, pattern in enumerate(patterns) if True or cnt_fn(idx)]

    sentences = [d2v.TaggedDocument(payloads, [rule]) for payloads, rule in mal_records]
    return d2v.Doc2Vec(sentences)


@DeprecationWarning
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
