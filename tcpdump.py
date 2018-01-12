import re
import sys
import os
import multiprocessing
import pickle
'''
[packet for packet in packets] 의 형태로 파싱
각 패킷은  [시간, 송신 IP.port, 수신 IP.port, payload] 의 형태로 저장되어 있다.
'''
def Unpack(path):
    '''
    tcpdump를 이용해 .unpacked 확장자로 언팩한다.
    '''
    try:
        os.system("tcpdump -A -r " + path + " > " + path + ".unpacked")
    except:
        print("tcpdump가 없음")

def Parse(filePath):
    '''
    각 패킷을 원소로 가지는 리스트를 반환한다.
    각 패킷은  [시간, 송신 IP.port, 수신 IP.port, payload] 의 형태로 저장되어 있다.
    '''
    with open(filePath) as f:
        lines = f.readlines()

    header = r"^(\d{2}:\d{2}:\d{2}\.\d{6}) IP (.+) > (.+?)(?=:\b)"
    # 00:00:00.000000 IP 1.1.1.1.portNum > 2.2.2.2.portNum
    # 가장 마지막 캡쳐를 살펴보자
    # .+?에서 ?는 +가 non-greedy 하게 소비하도록 한다. 따라서 긍정형 전방 탐색을 하는 과정에서 가장 처음으로 발견한 : 앞에서 수신 아이피.포트가 추출된다.
    hdrPattern = re.compile(header)
    timePattern = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d{6}") #시간정보만 확인
    ret = []
    bTestPacket = False
    cnt = 0
    length = len(lines)

    for idx, line in enumerate(lines):
        print("\rProgress: {}/{} ({:.1f}%)".format(idx + 1, length, (idx+1)/length * 100), end='')

        headerInfo = hdrPattern.search(line)
        if headerInfo:
            bTestPacket = False
            #add time, send-ip, receive-ip
            packet = [headerInfo.group(i) for i in range(1, 3 + 1)]
            packet.append("")

            ret.append(packet)
        elif bTestPacket or timePattern.search(line):       #test packet 같은 무의미한 패킷 패스
            bTestPacket = True
            continue
        else:
            ret[-1][-1] += line
                
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
    p = multiprocessing.Pool()
    #p.map(Unpack, sys.argv[1:])
    packets_list = p.map(Parse, sys.argv[1:])
    names = [name+".ser" for name in sys.argv[1:]]
    #p.starmap(Serialize, zip(names, packets_list))
    for packets in packets_list:
        for packet in packets:
            print(packet[-1])

    print("Done!")
    return

if __name__ == "__main__":
    main()
