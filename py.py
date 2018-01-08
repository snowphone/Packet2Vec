'''
가정: argv로 snort_rule에서 잡힌 string이 들어올 것

'''
from math import gcd
import sys
import pickle
from functools import *
# pip install gensim!!!
import gensim.models.word2vec as wv
import pickle

def main():
    '''
    inputfile = "sample.txt"
    sentences = Input(inputfile)
    print(*sentences)
    '''

    return


def Input(inputfile, wordsize=10):
    '''
    packet 전체를 리스트로 받는다. 
    각 패킷을 wordsize 단위로 끊어 한 단어로 취급한다.
    한 패킷을 하나의 문장으로 취급한다.
    '''
    # 학습 단계
    f = open(inputfile, mode="rb")   #hex로 열기
    sentences = f.readlines()
    ret = [reduce(lambda x,y: x+y, sentences[i:i+wordsize]) for i in range(0,len(sentences),wordsize)]
    ret = [str(s,"utf8") for s in ret]

    f.close()

    return ret

    
def toHex(string):
    return string.encode("hex")

def toStr(hexa):
    return hexa.decode("hex")

    
if __name__ == "__main__":
    main()