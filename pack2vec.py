import pickle
import re
import sys
import multiprocessing

import Parser
import Snort

dbg=True

def main():
    '''
    인자: regex_pattern, packets1, packets2, ...
    출력: '덤프 이름'.mal 형태
    '''
    if len(sys.argv) < 3:
        #sample data
        print("No arguments")
        if dbg:
            sys.argv = [None, "community_snort_rule/pcre", "../outside.tcpdump_tue.ascii_out.ser"]
        else:
            return

    with open(sys.argv[1]) as f:
        rules = [rule.rstrip() for rule in f.readlines()]
    patterns = [re.compile(rule) for rule in rules]

    [Snort.Serialize(path, Snort.Search(Parser.Deserialize(path), patterns)) 
    for path in sys.argv[2:] ]

    return

if __name__ == "__main__":
    main()