package rtpParse

import (
	"fmt"
	"io"
	"os"
	"testing"
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
