package librsync

import (
	//"bufio"
	"bytes"
	"encoding/binary"
	"github.com/balena-os/circbuf"
	"io"
)

func Delta(sig *SignatureType, input io.Reader, output io.Writer) error {

	if err := binary.Write(output, binary.BigEndian, DELTA_MAGIC); err != nil {
		return err
	}

	m := match{output: output}
	weakSum := NewRollsum()
	block, _ := circbuf.NewBuffer(int64(sig.blockLen))

	lbuf := make([]byte, sig.blockLen)
	sbuf := make([]byte, 1)
	if len, err := input.Read(lbuf); err != nil {
		return err
	} else {
		block.Write(lbuf[:len])
		weakSum.Update(lbuf[:len])
	}
	pos := 0
	for {
		pos += 1

		tb := block.Bytes()
		tsum := weakSum.Digest()
		matched := false
		if blockIdx, ok := sig.weak2block[tsum]; ok {
			strong2, _ := CalcStrongSum(tb, sig.sigType, sig.strongLen)
			if bytes.Equal(sig.strongSigs[blockIdx], strong2) {
				matched = true
				if err := m.add(MATCH_KIND_COPY, uint64(blockIdx)*uint64(sig.blockLen), uint64(sig.blockLen)); err != nil {
					return err
				}
				tbuf := make([]byte, sig.blockLen)
				if len, err := input.Read(tbuf); err != nil {
					return err
				} else {
					weakSum.Reset()
					block.Reset()
					block.Write(tbuf[:len])
					weakSum.Update(tbuf[:len])
				}
			}
		}
		if !matched {
			_ , err := input.Read(sbuf)
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			head, _ := block.Get(0)
			weakSum.Rotate(head, sbuf[0])
			block.WriteByte(sbuf[0])
			if err := m.add(MATCH_KIND_LITERAL, uint64(head), 1); err != nil {
				return err
			}
		}
	}

	for _, b := range block.Bytes() {
		err := m.add(MATCH_KIND_LITERAL, uint64(b), 1)
		if err != nil {
			return err
		}
	}

	if err := m.flush(); err != nil {
		return err
	}

	return binary.Write(output, binary.BigEndian, OP_END)
}

func DeltaR(sigIn io.Reader, i io.Reader, out io.Writer) error {
	ret := SignatureType{}
	ret.weak2block = make(map[int32]int)
	if err := binary.Read(sigIn, binary.BigEndian, &ret.sigType); err != nil {
		return err
	}
	if err := binary.Read(sigIn, binary.BigEndian, &ret.blockLen); err != nil {
		return err
	}
	if err := binary.Read(sigIn, binary.BigEndian, &ret.strongLen); err != nil {
		return err
	}

	var weak int32
	for {
		block := make([]byte, ret.strongLen)
		if err := binary.Read(sigIn, binary.BigEndian, &weak); err == io.ErrUnexpectedEOF || err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if _, err := sigIn.Read(block); err != nil {
			return err
		}
		ret.weak2block[weak] = len(ret.strongSigs)
		ret.strongSigs = append(ret.strongSigs, block)
	}

	return Delta(&ret, i, out)
}

