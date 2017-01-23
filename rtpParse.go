package rtpParse

// byte order big_endian
type Rtp struct {
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
}
