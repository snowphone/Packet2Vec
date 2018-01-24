import multiprocessing
from functools import wraps
import tcpdump
import pickle
from time import time
import re
from itertools import repeat, starmap

def tracer(func):
	@wraps(func)
	def wrapper(*args):
		print("\nenter {}".format(func.__name__))
		ret = func(*args)
		print("\nescape {}".format(func.__name__))
		return ret
	return wrapper

def tracer_class(object):
	'''
	class version of tracer
	'''
	def __init__(self, func):
		self.func= func
		functools.update_wrapper(self.func, func)
		return
	
	def __call__(self, *args, **kwargs):
		print("\nenter {}".format(self.func.__name__))
		ret = self.func(*args, **kwargs)
		print("\nescape {}".format(self.func.__name__))
		return ret

class _Inspector(object):
	'''
	파이썬의 멀티프로세싱 모듈을 사용하기 위해선 전역으로 선언된 객체를 이용해야 한다.
	따라서 클래스를 이용하여 nested function을 구현하였다.
	'''
	def __init__(self, pattern):
		self.pattern = pattern
		return

	def __call__(self, payload):
		'''
		정규식에 payload가 일치하는지 찾고 일치한다면 그 payload를 반환한다.
		'''
		if self.pattern.search(payload):
			return payload
		else:
			return None

def traceProgress(func):
	'''
	함수가 호출된 횟수를 콘솔에 반환한다.
	병렬 프로그래밍에 적합하도록 짜여졌다.
	'''

	@wraps(func)
	def wrapper(*args, **kwargs):
		begin = time()
		ret = func(*args, **kwargs)
		end=time()
		print("\rjob: {} elapsed time: {:.3f} seconds total elapsed time: {:.3f} seconds".format(func.__name__, end - begin, end - wrapper.begin), end='')
		return ret
	wrapper.begin = time()
	return wrapper

@traceProgress 
def Inspect_packets(pattern, packets):
	'''
	하나의 정규식과 여러 패킷이 들어왔을 때, 정규식에 매칭되는 모든 패킷들을 반환한다.
	반환 형식은 매칭된 패킷들의 리스트이다.
	'''
	payloads = [packet[-1] for packet in packets]
	length = len(payloads)
	'''
	pool = multiprocessing.Pool()
	return [payload 
			for payload 
			in pool.starmap(_Inspector(pattern, length), enumerate(payloads, 1))
			if payload is not None]
			'''
	return tuple(payload for payload in map(_Inspector(pattern), payloads) if payload is not None)
	
def ExtractRules(snort_rule_path):
	'''
	인자: snort_rule 파일 경로
	정규식을 추출해 리스트로 반환한다.
	'''
	f = open(snort_rule_path)
	lines = f.readlines()
	regexEngn = re.compile(r'(?<=pcre:").*?(?="[;,])')

	ret = [pattern.group() for pattern in map(regexEngn.search, lines) if pattern]
	f.close()
	return ret

@tracer_class  
def Parallel_Inspect(patterns, packets):
	'''
	인자: 정규식 엔진 리스트, 패킷 리스트
	여려 정규식 패턴이 들어왔을 때, 병렬적으로 Inspect_packets을 수행한다.
	(걸러진 payload 리스트, 정규식)으로 이루어진 리스트를 반환한다.
	'''
	with multiprocessing.Pool(6) as pool:
		ret_list = pool.starmap(Inspect_packets, zip(patterns, repeat(packets)))
	return tuple((payloads, pattern.pattern) for payloads, pattern in zip(ret_list, patterns))


if __name__ == "__main__":
	from sys import argv

	with open(argv[1]) as f:
		rules = f.readlines()
		rules = [rule.rstrip() for rule in rules]
	patterns = (re.compile(rule) for rule in rules)
	packets = tcpdump.Deserialize(argv[2])
	Parallel_Inspect(patterns, packets)
