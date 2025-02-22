package msgpack

import (
	"fmt"

	"github.com/keybase/go-codec/codec"
)

func CodecHandle() *codec.MsgpackHandle {
	var mh codec.MsgpackHandle
	mh.WriteExt = true
	return &mh
}

func EncodeCanonical(src interface{}) (dst []byte, err error) {
	ch := CodecHandle()
	ch.Canonical = true
	err = codec.NewEncoderBytes(&dst, ch).Encode(src)
	return dst, err
}

func Decode(dst interface{}, src []byte) (err error) {
	ch := CodecHandle()
	return codec.NewDecoderBytes(src, ch).Decode(dst)
}

func Encode(src interface{}) (dst []byte, err error) {
	ch := CodecHandle()
	err = codec.NewEncoderBytes(&dst, ch).Encode(src)
	return dst, err
}

// Decode data into out, but make sure that all bytes in data are
// used.
func DecodeAll(data []byte, handle *codec.MsgpackHandle, out interface{}) error {
	decoder := codec.NewDecoderBytes(data, handle)
	err := decoder.Decode(out)
	if err != nil {
		return err
	}

	if decoder.NumBytesRead() != len(data) {
		return fmt.Errorf("Did not consume entire buffer: %d byte(s) left", len(data)-decoder.NumBytesRead())
	}
	return nil
}

func IsEncodedMsgpackArray(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	b := data[0]
	return (b >= 0x90 && b <= 0x9f) || b == 0xdc || b == 0xdd
}

func IsJSONObject(data []byte) bool {
	return len(data) > 0 && data[0] == '{'
}
