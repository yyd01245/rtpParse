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

var ADTS = []uint8{0xFF, 0xF1, 0x00, 0x00, 0x00, 0x00, 0xFC}

// interface for protocol
type StreamProtocol interface {
	GetProtocolHead() interface{}
	GetPacketLen() int
	GetValue() []byte
}

// byte order big_endian
type RtpHead struct {
	Version    byte
	Padding    byte
	Extension  byte
	Csrccount  byte
	Markerbit  byte
	Typ        byte
	Seq_number uint16
	Timestamp  uint32
	Ssrc       uint32
	Csrc       [16]uint32
	HeaderLen  uint16
}

// RTP struct include head method.
type Rtp struct {
	Header RtpHead
	Len    int
	Value  []byte
}

func (r *Rtp) GetProtocolHead() (any interface{}) {
	return r.Header
}
func (r *Rtp) GetPacketLen() int {
	return r.Len
}
func (r *Rtp) GetValue() []byte {
	return r.Value
}
func New(h *RtpHead, l int, data []byte) (r *Rtp) {
	r = new(Rtp)
	r.Header = *h
	r.Len = l
	r.Value = make([]byte, r.Len)
	copy(r.Value, data)
	return
}

// data big_endian
func GetRtpHead(data []byte) (h *RtpHead, err error) {
	if len(data) < 12 {
		// len error
		h = nil
		// set error
		err = fmt.Errorf("data len less 12")
		return
	}
	h = new(RtpHead)
	h.Version = data[0] >> 6
	h.Padding = data[0] >> 5 & 0x01
	h.Extension = data[0] >> 4 & 0x01
	h.Csrccount = (data[0] << 4) >> 4
	h.Markerbit = data[1] >> 7
	h.Typ = (data[1] << 1) >> 1
	h.Seq_number = binary.BigEndian.Uint16(data[2:4])
	h.Timestamp = binary.BigEndian.Uint32(data[4:8])
	h.Ssrc = binary.BigEndian.Uint32(data[8:12])
	h.HeaderLen = 12
	err = nil
	return
}

type NaluHead struct {
	F         byte
	NRI       byte
	TYPE      byte
	HeaderLen uint16
}

type FragUnitHead struct {
	S         byte
	E         byte
	R         byte
	TYPE      byte
	HeaderLen uint16
}

type StapUnitHead struct {
	NaluSize  uint16
	HeaderLen uint16
}

type NaluBody struct {
	Header     NaluHead
	UnitHeader FragUnitHead
	Len        int
	Value      []uint8
}

func (r *NaluBody) GetProtocolHead() (any interface{}) {
	return r.Header
}
func (r *NaluBody) GetPacketLen() int {
	return r.Len
}
func (r *NaluBody) GetValue() []uint8 {
	return r.Value
}

func GetNALUHead(data []uint8) (h *NaluHead, err error) {
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
	h.HeaderLen = 1
	err = nil
	return
}

func GetFUAHead(data []uint8) (h *FragUnitHead, err error) {
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
	h.HeaderLen = 1
	return
}

func GetStapAHead(data []uint8) (h *StapUnitHead, err error) {
	if len(data) < 2 {
		// len error
		h = nil
		// set error
		err = fmt.Errorf("data len less 2")
		return
	}
	h = new(StapUnitHead)
	fmt.Printf("statp data : %x %x %x %x \n", data[0], data[1], data[2], data[3])
	h.NaluSize = binary.BigEndian.Uint16(data[0:2])
	h.HeaderLen = 2
	return
}

type UpyPrivate struct {
	TYPE     byte
	MTYPE    byte
	RTYPE    byte
	Reserver uint16
	Len      uint16
	ClientID uint32

	HeaderLen uint16
}

func GetPrivateAHead(data []uint8) (h *UpyPrivate, err error) {
	if len(data) < 12 {
		// len error
		h = nil
		// set error
		err = fmt.Errorf("data len less 2")
		return
	}
	h = new(UpyPrivate)
	fmt.Printf("private data : %x %x %x %x \n", data[0], data[1], data[2], data[3])
	h.TYPE = data[0] >> 6
	h.MTYPE = data[0] >> 4 & 0x03
	h.RTYPE = data[0] >> 2 & 0x03
	// reserver 10 bite
	h.Len = binary.BigEndian.Uint16(data[2:4])
	h.ClientID = binary.BigEndian.Uint32(data[4:8])

	h.HeaderLen = 8
	return
}
