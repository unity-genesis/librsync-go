package librsync

type Rollsum struct {
	count  uint64
	s1, s2 uint32
}

const ROLLSUM_CHAR_OFFSET = 31

func WeakChecksum(data []byte) int32 {
	var sum Rollsum
	sum.Update(data)
	return sum.Digest()
}

func NewRollsum() Rollsum {
	return Rollsum{}
}

func (r *Rollsum) Update(p []byte) {
	l := len(p)

	for n := 0; n < l; {
		if n+15 < l {
			for i := 0; i < 16; i++ {
				r.s1 += uint32(p[n+i])
				r.s2 += r.s1
			}
			n += 16
		} else {
			r.s1 += uint32(p[n])
			r.s2 += r.s1
			n += 1
		}
	}

	r.s1 += uint32(l * ROLLSUM_CHAR_OFFSET)
	r.s2 += uint32(((l * (l + 1)) / 2) * ROLLSUM_CHAR_OFFSET)
	r.count += uint64(l)
}

func (r *Rollsum) Rotate(out, in byte) {
	r.s1 += uint32(in) - uint32(out)
	r.s2 += r.s1 - uint32(r.count)*(uint32(out)+uint32(ROLLSUM_CHAR_OFFSET))
}

func (r *Rollsum) Rollin(in byte) {
	r.s1 += uint32(in) + uint32(ROLLSUM_CHAR_OFFSET)
	r.s2 += r.s1
	r.count += 1
}

func (r *Rollsum) Rollout(out byte) {
	r.s1 -= uint32(out) + uint32(ROLLSUM_CHAR_OFFSET)
	r.s2 -= uint32(r.count) * (uint32(out) + uint32(ROLLSUM_CHAR_OFFSET))
	r.count -= 1
}

func (r *Rollsum) Digest() int32 {
	return (int32(r.s2) << 16) | (int32(r.s1) & 0xffff)
}

func (r *Rollsum) Reset() {
	r.count = 0
	r.s1 = 0
	r.s2 = 0
}
