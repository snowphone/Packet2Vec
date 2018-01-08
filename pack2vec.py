import Parser
import re
import sys

def main():
    '''
    인자: 직렬화된 패킷 덤프들
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
        packets = Parser.Deserialize(name)
        for packet in packets:
            payload = packet[-1]
            for pattern in patterns:
                malware_payload = pattern.search(payload)
                if not malware_payload:
                    continue
                print("Rule:", regex_rule, 
                "\nDetected pattern:", malware_payload.group(),
                "\nPayload:", payload)
                break   #examine next payload
    return

if __name__ == "__main__":
    main()