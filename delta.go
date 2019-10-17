package librsync

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"github.com/balena-os/circbuf"
	"io"
)

func Delta(sig *SignatureType, i io.Reader, output io.Writer) error {
	input := bufio.NewReader(i)

	err := binary.Write(output, binary.BigEndian, DELTA_MAGIC)
	if err != nil {
		return err
	}

	prevByte := byte(0)
	m := match{output: output}

	weakSum := NewRollsum()
	block, _ := circbuf.NewBuffer(int64(sig.blockLen))
	pos := 0

	for {
		pos += 1
		in, err := input.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if block.TotalWritten() > 0 {
			prevByte, err = block.Get(0)
			if err != nil {
				return err
			}
		}
		block.WriteByte(in)
		weakSum.Rollin(in)

		if weakSum.count < uint64(sig.blockLen) {
			continue
		}

		if weakSum.count > uint64(sig.blockLen) {
			err := m.add(MATCH_KIND_LITERAL, uint64(prevByte), 1)
			if err != nil {
				return err
			}
			weakSum.Rollout(prevByte)
		}

		if blockIdx, ok := sig.weak2block[weakSum.Digest()]; ok {
			strong2, _ := CalcStrongSum(block.Bytes(), sig.sigType, sig.strongLen)
			if bytes.Equal(sig.strongSigs[blockIdx], strong2) {
				weakSum.Reset()
				block.Reset()
				err := m.add(MATCH_KIND_COPY, uint64(blockIdx)*uint64(sig.blockLen), uint64(sig.blockLen))
				if err != nil {
					return err
				}
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

	block := make([]byte, ret.strongLen)
	var weak uint32
	for {
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

