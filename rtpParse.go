package rtpParse

import (
	"encoding/binary"
	"fmt"
)

//	"github.com/akrennmair/gopcap"
const (
	PLAYLOAD_FU_A   = 28
	PLAYLOAD_STAP_A = 24
)

const (
	PLAYLOAD_VIDEO = 107
	PLAYLOAD_AUDIO = 111
)

var h264StartCode = []uint8{0x0, 0x0, 0x0, 0x01, 0x0}

// interface for protocol
type StreamProtocol interface {
	getProtocolHead() interface{}
	getPacketLen() int
	getValue() []byte
}

// byte order big_endian
type RtpHead struct {
	version    byte
	padding    byte
	extension  byte
	csrccount  byte
	markerbit  byte
	typ        byte
	seq_number uint16
	timestamp  uint32
	ssrc       uint32
	csrc       [16]uint32
	headerLen  uint16
}

// RTP struct include head method.
type Rtp struct {
	header RtpHead
	len    int
	value  []byte
}

func (r *Rtp) getProtocolHead() (any interface{}) {
	return r.header
}
func (r *Rtp) getPacketLen() int {
	return r.len
}
func (r *Rtp) getValue() []byte {
	return r.value
}
func New(h *RtpHead, l int, data []byte) (r *Rtp) {
	r = new(Rtp)
	r.header = *h
	r.len = l
	r.value = make([]byte, r.len)
	copy(r.value, data)
	return
}

// data big_endian
func getRtpHead(data []byte) (h *RtpHead, err error) {
	if len(data) < 12 {
		// len error
		h = nil
		// set error
		err = fmt.Errorf("data len less 12")
		return
	}
	h = new(RtpHead)
	h.version = data[0] >> 6
	h.padding = data[0] >> 5 & 0x01
	h.extension = data[0] >> 4 & 0x01
	h.csrccount = (data[0] << 4) >> 4
	h.markerbit = data[1] >> 7
	h.typ = (data[1] << 1) >> 1
	h.seq_number = binary.BigEndian.Uint16(data[2:4])
	h.timestamp = binary.BigEndian.Uint32(data[4:8])
	h.ssrc = binary.BigEndian.Uint32(data[8:12])
	h.headerLen = 12
	err = nil
	return
}

type NaluHead struct {
	F         byte
	NRI       byte
	TYPE      byte
	headerLen uint16
}

type FragUnitHead struct {
	S         byte
	E         byte
	R         byte
	TYPE      byte
	headerLen uint16
}

type StapUnitHead struct {
	naluSize  uint16
	headerLen uint16
}

type NaluBody struct {
	header     NaluHead
	unitHeader FragUnitHead
	len        int
	value      []uint8
}

func (r *NaluBody) getProtocolHead() (any interface{}) {
	return r.header
}
func (r *NaluBody) getPacketLen() int {
	return r.len
}
func (r *NaluBody) getValue() []uint8 {
	return r.value
}

func getNALUHead(data []uint8) (h *NaluHead, err error) {
	if len(data) < 2 {
		// len error
		h = nil
		// set error
		err = fmt.Errorf("data len less 2")
		return
	}
	h = new(NaluHead)
	h.F = data[0] >> 7 & 0x01
	h.NRI = data[0] >> 5 & 0x03
	h.TYPE = data[0] & 0x1F
	h.headerLen = 1
	err = nil
	return
}

func getFUAHead(data []uint8) (h *FragUnitHead, err error) {
	if len(data) < 2 {
		// len error
		h = nil
		// set error
		err = fmt.Errorf("data len less 2")
		return
	}
	h = new(FragUnitHead)
	h.S = data[0] >> 7 & 0x01
	h.E = data[0] >> 6 & 0x01
	h.R = data[0] >> 5 & 0x01
	h.TYPE = data[0] & 0x1F
	h.headerLen = 1
	return
}

func getStapAHead(data []uint8) (h *StapUnitHead, err error) {
	if len(data) < 2 {
		// len error
		h = nil
		// set error
		err = fmt.Errorf("data len less 2")
		return
	}
	h = new(StapUnitHead)
	fmt.Printf("statp data : %x %x %x %x \n", data[0], data[1], data[2], data[3])
	h.naluSize = binary.BigEndian.Uint16(data[0:2])
	h.headerLen = 2
	return
}

type upyPrivate struct {
	TYPE     byte
	mTYPE    byte
	rTYPE    byte
	reserver uint16
	len      uint16
	clientID uint32

	headerLen uint16
}

func getPrivateAHead(data []uint8) (h *upyPrivate, err error) {
	if len(data) < 12 {
		// len error
		h = nil
		// set error
		err = fmt.Errorf("data len less 2")
		return
	}
	h = new(upyPrivate)
	fmt.Printf("private data : %x %x %x %x \n", data[0], data[1], data[2], data[3])
	h.TYPE = data[0] >> 6
	h.mTYPE = data[0] >> 4 & 0x03
	h.rTYPE = data[0] >> 2 & 0x03
	// reserver 10 bite
	h.len = binary.BigEndian.Uint16(data[2:4])
	h.clientID = binary.BigEndian.Uint32(data[4:8])

	h.headerLen = 8
	return
}
