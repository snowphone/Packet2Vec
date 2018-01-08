import Parser
import re
import sys

def main():
    '''
    인자: 직렬화된 패킷 덤프들
    출력: '덤프 이름'.pattern 형태
    '''
    if len(sys.argv) <= 1:
        #sample data
        sys.argv = [None, "../inside.tcpdump_fri.ascii_out.ser"]

    with open("pcre") as f:
        rules = f.readlines().rstrip()
    patterns = []   #snort_rule pcre patterns
    for rule in rules:
        patterns.append(re.compile(rule))

    for name in sys.argv[1:]:
        output = open(name+".pattern")
        packets = Parser.Deserialize(name)
        for packet in packets:
            print("checking for", packets[0], "last packet:", packets[-1][0])
            payload = packet[-1]
            for pattern in patterns:
                malware_payload = pattern.search(payload)
                if not malware_payload:
                    continue
                log = "Rule: "+ regex_rule+ "\nDetected pattern: "+ malware_payload.group()+ "\nPayload: "+ payload + "\n\n"
                output.write(log)

                break   #examine next payload
        output.close()
    return

if __name__ == "__main__":
    main()