import Snort
import Parser
import Inspect
import sys
import gensim.models.word2vec as w2v

def main():
    week = ["mon", "tue", "wed", "thu"]
    paths = ["trainData/" + a + "side.tcpdump_" + day + ".ascii_out.ser_malware" for day in week for a in ["in", "out"]]

    trainData = []

    for path in paths:
        f = open(path,encoding="utf8")
        trainData.append(f.read())
        f.close()

    model = w2v.Word2Vec(sys.argv[1])

    for path in sys.argv[2:]:
        packets = Parser.Deserialize(path)
        sentences = [packet[-1] for packet in packets]

        for time,rule, matched, payload in packets:
            print(model.most_similar(positive=[matched]))

    return

if __name__ == "__main__":
    main()