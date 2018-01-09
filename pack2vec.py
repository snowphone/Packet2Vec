import Parser
import pickle
import re
import sys
import multiprocessing

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

    with multiprocessing.pool.Pool(24) as pool:
        fn = lambda name: Snort(Parser.Deserialize(name), rules, patterns).Search(name+".malware")
        list(pool.map_async(fn, sys.argv[2:]))    
    return

class Snort:
    def __init__(self, packets, rules, patterns):
        self.packets = packets
        self.log = []
        self.rules = rules  #정규식 스트링
        self.patterns = patterns #컴파일된 정규식 엔진
        return

    def __serialize__(self, filename):
        with open(filename,mode="wb+") as output:
            pickle.dump(self.log, output)
        return


    def Search(self, outputName=None):
        '''
        snort_rule에 걸리는 패킷을 모아 (패킷 시각, 정규식, 일치한 패턴, 페이로드)를 직렬화해 저장한다.
        '''
        for packet in self.packets:
            print("checking for", packet[0], ", last packet:", self.packets[-1][0])
            payload = packet[-1]
            for regexEngn, regexRule in zip(self.patterns, self.rules):
                malware_payload = regexEngn.search(payload)
                if not malware_payload:
                    continue
                self.log.append((packet[0], regexRule, malware_payload.group(0), payload))
                print("---Pattern matched---")
                break
        self.__serialize__(outputName)
        return

if __name__ == "__main__":
    main()