import re
import sys
import pickle
'''
tcpdump 파일을 파이썬에서 다룰수 있게 하는 것이 목표.

변경점: 인자로 input, output 줄 경우 serialize 해서 리스트 저장
변경점: 수신 아이피-포트에 non-greedy 캡쳐를 사용하여 가장 처음 발견하는 : 앞에서 멈추도록 함
변경점: packet의 길이 요소를 제거
'''

class Parser:
    '''
    [packet for packet in packets] 의 형태로 파싱
    각 패킷은  [시간, 송신 IP.port, 수신 IP.port, payload] 의 형태로 저장되어 있다.
    Get() 메소드를 통하여 리스트를 가져올 수 있다.
    '''
    def __init__(self, filename, mode="ascii"):
        '''
        인자: tcpdump를 이용하여 언팩한 파일의 이름
        mode: tcpdump 옵션에 따라 달라진다.
        -A 옵션 사용시  'ascii'.
        -x 옵션 사용시 'hex'
        hex의 경우 tcpdump 출력창에 나오는 인덱스를 지우고 저장한다.
        '''
        self.mode = mode
        f = open(filename,mode='r', encoding="utf8")
        self.lines = f.readlines()
        f.close()
        return

    def Get(self):
        '''
        각 패킷을 원소로 가지는 list 반환
        각 패킷은  [시간, 송신 IP.port, 수신 IP.port, payload] 의 형태로 저장되어 있다.
        '''
        header = r"^(\d{2}:\d{2}:\d{2}\.\d{6}) IP (.+) > (.+?)(?=:\s)"
        # 00:00:00.000000 IP 1.1.1.1.portNum > 2.2.2.2.portNum
        # 가장 마지막 캡쳐를 살펴보자
        # .+?에서 ?는 +가 non-greedy 하게 소비하도록 한다. 따라서 긍정형 전방 탐색을 하는 과정에서 가장 처음으로 발견한 : 앞에서 수신 아이피.포트가 추출된다.
        hdrPattern = re.compile(header)
        testpacket = re.compile(r"^\d{2}:\d{2}:\d{2}[.]\d{6}\b")
        hexIndex = re.compile(r"\b0x[0-9a-fA-F]{4}:\b")
        ret = []
        bTestPacket = False
        cnt = 0
        length = len(self.lines)
        threshold = 0.1

        for line in self.lines:
            '''
            cnt += 1
            if cnt/length  >= threadhold:
                print("진행률:", cnt/length * 100, "%")
                threadhold += 0.1
            '''

            headerInfo = hdrPattern.search(line)
            if headerInfo:
                bTestPacket = False
                #add time, send-ip, receive-ip
                packet = [headerInfo.group(i) for i in range(1,3+1) ]
                packet.append("")

                ret.append(packet)
            elif bTestPacket or testpacket.search(line):       #test packet 같은 무의미한 패킷 패스
                bTestPacket = True
                continue
            else:
                if self.mode == "ascii":
                    ret[-1][-1] += line
                else:
                    ret[-1][-1] += hexIndex.sub("", line)     
                    
        return ret


def Deserialize(filename):
    '''
    pickle을 통해 역 직렬화 함
    '''
    with open(filename, "rb") as f:
        ret = pickle.load(f)
    return ret

def Serialize(path, data):
    with open(path,mode="wb+") as output:
        pickle.dump(data, output)
    return

def main():
    '''
    인자: dump 파일, output 파일 이름, 파싱 방법(ascii, hex)
    Pickle을 통해 binary로 직렬화
    '''
    if len(sys.argv) > 2:
        filename = sys.argv[1]
        output = sys.argv[2]
        parser = Parser(filename)
        packets = parser.Get()
        with open(output, "wb") as f:
            pickle.dump(packets, f)
    else:
        filename = "hexoutput"
        parser = Parser(filename)
        packets = parser.Get()
        for packet in packets:
            print("시간:", packet[0])
            print("송신자:", packet[1])
            print("수신자:", packet[2])
            print("-------------Payload----------")
            print(packet[-1])
            print()

if __name__ == "__main__":
    main()
