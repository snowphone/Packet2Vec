import pickle
import re
import sys
import multiprocessing

import Parser
import Snort

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

    with multiprocessing.Pool(4) as pool:
        fn = lambda path: Snort.Search(path+".malware", Parser.Deserialize(path), rules, patterns)
        pool.map_async(fn, sys.argv[2:])
    return

if __name__ == "__main__":
    main()