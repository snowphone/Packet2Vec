import Parser
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

    patterns = CompilePatterns(sys.argv[1])

    for name in sys.argv[2:]:
        packets = Parser.Deserialize(name)
        snort = Snort(packets,patterns)
        snort.Search(name+".mal")
    return


def CompilePatterns(filename):
    with open(filename) as f:
        rules = f.readlines()
    patterns = []   #snort_rule pcre patterns
    for rule in rules:
        patterns.append(re.compile(rule.rstrip()))
    return patterns

class Snort:
    def __init__(self, packets, patterns):
        self.packets = packets
        self.patterns = patterns
        return

    def Search(self, outputName):
        output = open(outputName,mode="w+")
        for packet in self.packets:
            print("checking for", packet[0], ", last packet:", self.packets[-1][0])
            payload = packet[-1]
            for pattern in self.patterns:
                malware_payload = pattern.search(payload)
                if not malware_payload:
                    continue
                log = "Time: "+ packet[0] + "\nDetected pattern: "+ malware_payload.group()+ "\nPayload: "+ payload + "\n\n"
                output.write(log)
                print("---Pattern matched---")
                break
        output.close()
        return

if __name__ == "__main__":
    main()