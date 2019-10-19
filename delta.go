package librsync

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"

	"github.com/balena-os/circbuf"
)

func Delta(sig *SignatureType, i io.Reader, output io.Writer) error {
	input := bufio.NewReader(i)

	if err := binary.Write(output, binary.BigEndian, DELTA_MAGIC); err != nil {
		return err
	}

	m := match{output: output}
	weakSum := NewRollsum()
	block, _ := circbuf.NewBuffer(int64(sig.blockLen))

	buf := make([]byte, sig.blockLen)
	if len, err := input.Read(buf); err != nil {
		return err
	} else {
		block.Write(buf[:len])
		weakSum.Update(buf[:len])
	}

	pos := 0
	for {
		pos += 1
		if blockIdx, ok := sig.weak2block[weakSum.Digest()]; ok {
			strong2, _ := CalcStrongSum(block.Bytes(), sig.sigType, sig.strongLen)
			if bytes.Equal(sig.strongSigs[blockIdx], strong2) {
				weakSum.Reset()
				block.Reset()
				if err := m.add(MATCH_KIND_COPY, uint64(blockIdx)*uint64(sig.blockLen), uint64(sig.blockLen)); err != nil {
					return err
				}
				if len, err := input.Read(buf); err != nil {
					return err
				} else {
					block.Write(buf[:len])
					weakSum.Update(buf[:len])
				}
			}
		} else {
			in , err := input.ReadByte()
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			head, _ := block.Get(0)
			weakSum.Rotate(head, in)
			block.WriteByte(in)
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
	ret.weak2block = make(map[uint32]int)
	if err := binary.Read(sigIn, binary.BigEndian, &ret.sigType); err != nil {
		return err
	}
	if err := binary.Read(sigIn, binary.BigEndian, &ret.blockLen); err != nil {
		return err
	}
	if err := binary.Read(sigIn, binary.BigEndian, &ret.strongLen); err != nil {
		return err
	}

	var weak uint32
	for {
		if err := binary.Read(sigIn, binary.BigEndian, &weak); err == io.ErrUnexpectedEOF || err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		block := make([]byte, ret.strongLen)
		if _, err := sigIn.Read(block); err != nil {
			return err
		}
		ret.weak2block[weak] = len(ret.strongSigs)
		ret.strongSigs = append(ret.strongSigs, block)
	}

	return Delta(&ret, i, out)
}

