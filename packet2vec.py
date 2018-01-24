from snort import InspectInParallel, CompileRules
import tcpdump
import multiprocessing as mp
from functools import reduce, partial, update_wrapper 
from itertools import starmap, repeat
from tcpdump import Serialize, Deserialize
from sys import argv
import gensim.models.doc2vec as d2v
import re

def main():
	assert len(argv) >= 3
	rule_path = argv[1]
	packet_paths = argv[2:]
	'''
	rule_path = "community_snort_rule/pcre"
	packet_paths = ["inside.tcpdump_wed.ascii_out.ser"]
	'''

	with open(rule_path) as f:
		rules = f.readlines()
	rules = map(lambda x: x.rstrip(), rules)

	patterns = CompileRules(rules)


	with mp.Pool() as pool:
		packets_list = pool.map(Deserialize, packet_paths)

	packets = reduce(lambda x,y: x+y, packets_list)

	mal_records = InspectInParallel(patterns, packets)
	
	sentences = [d2v.TaggedDocument(payloads, [rule]) for payloads, rule in mal_records]
	Serialize("data.dat", sentences)
	print("\n", sentences)


def Train(patterns, packets):
	'''
	인자: 정규식 엔진 리스트, 패킷 리스트
	정규식 엔진들과 패킷들을 받아
	정규식을 doc ID로, 그 정규식에 걸러진 payload들을 단어로 삼아 학습시킨 Doc2Vec 객체를 반환한다.
	'''

	#리스트 내의 원소: (걸러진 패이로드들, 정규식)
	mal_records = InspectInParallel(patterns, packets)
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
