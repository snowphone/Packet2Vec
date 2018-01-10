import pickle
import re
import sys
import multiprocessing

import Parser
from Snort import *

def main():
    '''
    인자: regex_pattern, packets1, packets2, ...
    출력: '덤프 이름'.mal 형태
    '''
    if len(sys.argv) < 3:
        #sample data
        print("No arguments")
        return

    with open(sys.argv[1]) as f:
        rules = [rule.rstrip() for rule in f.readlines()]
    patterns = [re.compile(rule.rstrip()) for rule in rules]

    with multiprocessing.pool.Pool(4) as pool:
        fn = lambda name: Snort(Parser.Deserialize(name), rules, patterns).Search(name+".malware")
        list(pool.map_async(fn, sys.argv[2:]))    
    return


if __name__ == "__main__":
    main()