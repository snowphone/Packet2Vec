import Parser
import pickle
import re
import sys

def main():
    '''
    인자: regex_pattern, packets1, packets2, ...
    출력: '덤프 이름'.mal 형태
    '''
    if len(sys.argv) < 3:
        #sample data
        print("No arguments")
        return


    for name in sys.argv[2:]:
        packets = Parser.Deserialize(name)
        snort = Snort(packets)
        snort.CompilePatterns(sys.argv[1])
        snort.Search(name+".mal")
    return



class Snort:
    def __init__(self, packets):
        self.packets = packets
        self.patterns = []
        self.log = []
        self.rules = []
        return

    def __serialize__(self, filename):
        '''

        '''
        with open(filename,mode="wb+") as output:
            pickle.dump(self.log, output)
        return

    def CompilePatterns(self, filename):
        '''
        각각의 정규식을 읽어와 리스트에 저장한다.
        '''
        with open(filename) as f:
            self.rules = [rule.rstrip() for rule in f.readlines()]
        self.patterns = [re.compile(rule.rstrip()) for rule in self.rules]
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
