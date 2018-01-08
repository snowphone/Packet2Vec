import Parser
import re
import sys

def main():
    sys.argv = [None, "inside.tcpdump_fri.ascii_out.ser"]
    for name in sys.argv[1:]:
        packets = Parser.Deserialize(name)
        with open("pcre") as f:
            rules = f.readlines()
        for packet in packets:
            payload = packet[-1]
            for rule in rules:
                pattern = re.compile(rule.rstrip())
                ans = pattern.search(payload)
                if ans:
                    print("rule:", rule, "\npayload:", ans.group())
    return

if __name__ == "__main__":
    main()