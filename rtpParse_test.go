package rtpParse

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	TypeTest1 = iota
	TypeTest2
)

func FailWithError(t *testing.T, name string, err error) {
	fmt.Printf("[!] %s failed: %s\n", name, err.Error())
	t.FailNow()
}

func TestGetRtpHead(t *testing.T) {
	//descr := []byte("This is a test description.")
	// read file
	fi, err := os.Open("/Users/yanyandong/media_data/broadcast_test.rtp")
	if err != nil {
		err := fmt.Errorf("open file error")
		FailWithError(t, "TestGetRtpHead", err)
	}
	defer fi.Close()
	fmt.Printf("open file success \n")
	buf := make([]byte, 20)
	n, err := fi.Read(buf)
	if err != nil && err != io.EOF {
		FailWithError(t, "read file", err)
		panic(err)
	}
	data := make([]byte, n)
	copy(data, buf)
	header, _ := getRtpHead(data)
	fmt.Println(header)
	naluHead, _ := getNALUHead(data[12:])
	fmt.Println(naluHead)
	if naluHead.TYPE == 24 {
		stapHead, _ := getStapAHead(data[13:])
		fmt.Println(stapHead)
	} else if naluHead.TYPE == 28 {
		fuaHead, _ := getFUAHead(data[13:])
		fmt.Println(fuaHead)
	}

}

func TestPcapFile(t *testing.T) {
	//descr := []byte("This is a test description.")
	// read file
	fi, err := pcap.OpenOffline("/Users/yanyandong/media_data/udp_rtp.pcapng")
	if err != nil {
		err := fmt.Errorf("open file error")
		FailWithError(t, "TestGetRtpHead", err)
	}
	defer fi.Close()
	var filter string = "udp and port 2000"
	err = fi.SetBPFFilter(filter)
	if err != nil {
		err := fmt.Errorf("set filter file error")
		FailWithError(t, "set filter", err)
	}
	outFile := "/Users/yanyandong/media_data/gotest.264"
	out, err := os.Create(outFile)
	if err != nil {
		err := fmt.Errorf("creat %s file error", outFile)
		FailWithError(t, "TestPcapFile", err)
	}
	defer out.Close()
	fmt.Printf("open file success \n")

	flag := true
	packetSource := gopacket.NewPacketSource(fi, fi.LinkType())
	for packet := range packetSource.Packets() {
		if flag {
			fmt.Println("%x", packet.ApplicationLayer().Payload())
			flag = false
		}
		var data []uint8 = packet.ApplicationLayer().Payload()
		// need offset 2 packet last 2 bytes
		var offset int = 2
		var packetLen = len(data) - offset
		fmt.Println("packet len : ", packetLen)
		upyHead, _ := getPrivateAHead(data[offset:])
		fmt.Println("private head: ", *upyHead)
		offset += int(upyHead.headerLen)
		rtpHead, _ := getRtpHead(data[offset:])
		fmt.Println("rtp head: ", *rtpHead)
		offset += int(rtpHead.headerLen)
		if rtpHead.typ == PLAYLOAD_VIDEO {
			naluHead, _ := getNALUHead(data[offset:])
			fmt.Println("nalu head: ", *naluHead)
			offset += int(naluHead.headerLen)
			if naluHead.TYPE == PLAYLOAD_FU_A {
				fragunitHead, _ := getFUAHead(data[offset:])
				offset += int(fragunitHead.headerLen)
				fmt.Println("fu-a head: ", *fragunitHead)
				if fragunitHead.S == 1 {
					// started
					h264StartCode[4] = (h264StartCode[4]>>5 | 0x03) << 5
					h264StartCode[4] = h264StartCode[4] | fragunitHead.TYPE
					out.Write(h264StartCode)
					out.Sync()
				} else if fragunitHead.E == 1 {
					// end
				} else {
					// internal data
				}
				pLen := packetLen - offset
				fmt.Println("write fu-a len ", pLen)
				out.Write(data[offset:])
				out.Sync()
			} else if naluHead.TYPE == PLAYLOAD_STAP_A {
				lastLen := packetLen - offset
				for ; lastLen > 2; lastLen = packetLen - offset {
					stapHead, _ := getStapAHead(data[offset:])
					fmt.Println("stap-a head: ", *stapHead)
					offset += int(stapHead.headerLen)
					fmt.Println("stap-a nalsize ", stapHead.naluSize)
					out.Write(h264StartCode[:4])
					//	end :=
					out.Write(data[offset : offset+int(stapHead.naluSize)])
					out.Sync()
					fmt.Println("write stap-a len ", stapHead.naluSize)
					offset += int(stapHead.naluSize)

				}
			}
		} else if rtpHead.typ == PLAYLOAD_AUDIO {
			var audioSamprate int = 44100
			var audioChannel int = 2
			var audioBit int = 16
			switch audioSamprate {
			case 16000:
				ADTS[2] = 0x60
			case 32000:
				ADTS[2] = 0x54
			case 44100:
				ADTS[2] = 0x50
			case 48000:
				ADTS[2] = 0x4C
			case 96000:
				ADTS[2] = 0x40
			default:
				break
			}
			if audioChannel == 2 {
				ADTS[3] = 0x80
			} else {
				ADTS[3] = 0x40
			}
			recvLen := packetLen - offset
			fmt.Println(audioBit, recvLen)
			/*
			   ADTS[3] = (audioChannel==2)?0x80:0x40;

			   int len = recvLen - 16 + 7;
			   len <<= 5;//8bit * 2 - 11 = 5(headerSize 11bit)
			   len |= 0x1F;//5 bit    1
			   ADTS[4] = len>>8;
			   ADTS[5] = len & 0xFF;
			   *pBufOut = (char*)bufIn+16-7;
			   memcpy(*pBufOut, ADTS, sizeof(ADTS));
			   *pOutLen = recvLen - 16 + 7;

			   unsigned char* bufTmp = (unsigned char*)bufIn;
			   bool bFinishFrame = false;
			   if (bufTmp[1] & 0x80)
			   {
			       //DebugTrace::D("Marker");
			       bFinishFrame = true;
			   }
			   else
			   {
			       bFinishFrame = false;
			   }
			*/
		}

	}

}
