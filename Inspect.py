import sys
import Parser
import Snort


def Inspect(rulePath, *args):
    '''
    인자: regex_pattern, packets1, packets2, ...
    출력: '덤프 이름'.mal 형태
    '''

    with open(rulePath) as f:
        rules = [rule.rstrip() for rule in f.readlines()]
    patterns = [re.compile(rule) for rule in rules]

    [Snort.Serialize(path + "_malware", Snort.Search(Parser.Deserialize(path), patterns)) 
    for path in args ]

    return

if __name__ == "__main__":
    Inspect()