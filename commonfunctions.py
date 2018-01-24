'''
공통적으로 쓰이는 함수들을 모았다.
'''

import pickle
from functools import wraps, reduce
from time import time
from os import getpid

def tracer(func):
	''' 함수의 진입 및 퇴출을 추적및 시각화한다. '''
	@wraps(func)
	def wrapper(*args, **kwargs):
		print("PID: {},\tenter {}".format(getpid(), func.__name__))
		ret = func(*args, **kwargs)
		print("PID: {},\texit {}".format(getpid(), func.__name__))
		return ret
	return wrapper

def traceProgress(func):
	'''
	함수 호출에 걸리는 소요시간을 출력한다.
	'''
	@wraps(func)
	def wrapper(*args, **kwargs):
		begin = time()
		ret = func(*args, **kwargs)
		end=time()
		print("{}(PID: {}) takes {:.3f}s".format(func.__name__, getpid(), end - begin))
		return ret
	return wrapper

@tracer
def Deserialize(filename):
    ''' pickle을 통해 역 직렬화 함 '''
    with open(filename, "rb") as f:
        ret = pickle.load(f)
    return ret

@tracer
def Serialize(path, data):
    '''pickle을 통해 직렬화 하여 파일로 저장한다.'''
    with open(path,mode="wb+") as output:
        pickle.dump(data, output)
    return

@tracer
def Concat(*iterable):
    '''입력받은 인자들을 결합하여 반환한다.'''
    return reduce(lambda x,y: x+y, iterable)