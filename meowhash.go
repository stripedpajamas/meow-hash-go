package meowhash

type meowLane struct {
	L0 [16]byte
	L1 [16]byte
	L2 [16]byte
	L3 [16]byte
}

// go:noescape
func aesDecSi128(a, b, dst *byte)

// MeowHash32 returns a 32-bit hash of input
func MeowHash32(seed uint64, input []byte) [4]byte {
	h := meowHash1(seed, input)
	var output [4]byte
	copy(output[:], h.L0[:4])
	return output
}

// MeowHash64 returns a 64-bit hash of input
func MeowHash64(seed uint64, input []byte) [8]byte {
	h := meowHash1(seed, input)
	var output [8]byte
	copy(output[:], h.L0[:8])
	return output
}

// MeowHash128 returns a 128-bit hash of input
func MeowHash128(seed uint64, input []byte) [16]byte {
	h := meowHash1(seed, input)
	var output [16]byte
	copy(output[:], h.L0[:])
	return output
}

// MeowHash256 returns a 256-bit hash of input
func MeowHash256(seed uint64, input []byte) [32]byte {
	h := meowHash1(seed, input)
	var output [32]byte
	copy(output[:], h.L0[:])
	copy(output[16:], h.L1[:])
	return output
}

// MeowHash512 returns a 512-bit hash of input
func MeowHash512(seed uint64, input []byte) [64]byte {
	h := meowHash1(seed, input)
	var output [64]byte
	copy(output[:], h.L0[:])
	copy(output[16:], h.L1[:])
	copy(output[32:], h.L2[:])
	copy(output[48:], h.L3[:])
	return output
}

func meowHash1(seed uint64, src []byte) *meowLane {
	var iv meowLane
	length := uint64(len(src))

	// set first 8 bytes of each lane to seed
	putUint64(iv.L0[:], seed)
	putUint64(iv.L1[:], seed)
	putUint64(iv.L2[:], seed)
	putUint64(iv.L3[:], seed)
	// set second 8 bytes of each lane to (seed + length + 1)
	putUint64(iv.L0[8:], seed+length+1)
	putUint64(iv.L1[8:], seed+length+1)
	putUint64(iv.L2[8:], seed+length+1)
	putUint64(iv.L3[8:], seed+length+1)

	// initialize all 16 streams with the initialization vector
	S0123 := iv
	S4567 := iv
	S89AB := iv
	SCDEF := iv

	// handle as many full 256-byte blocks as possible
	blockCount := length >> 8
	length -= (blockCount << 8)
	idx := 0
	for ; blockCount > 0; idx += 256 {
		aesLoad(&S0123, src[idx:idx+64])
		aesLoad(&S4567, src[idx+64:idx+128])
		aesLoad(&S89AB, src[idx+128:idx+192])
		aesLoad(&SCDEF, src[idx+192:idx+256])
		blockCount--
	}

	// if residual data remains, hash one final 256-byte
	// block padded with the initialization vector
	if length > 0 {
		partial := []meowLane{iv, iv, iv, iv}
		for i := 0; i < 4 && length > 0; i++ {
			partialIdx := 0
			for length > 0 && partialIdx < 16 {
				partial[i].L0[partialIdx] = src[idx]
				partialIdx++
				idx++
				length--
			}
			partialIdx = 0
			for length > 0 && partialIdx < 16 {
				partial[i].L1[partialIdx] = src[idx]
				partialIdx++
				idx++
				length--
			}
			partialIdx = 0
			for length > 0 && partialIdx < 16 {
				partial[i].L2[partialIdx] = src[idx]
				partialIdx++
				idx++
				length--
			}
			partialIdx = 0
			for length > 0 && partialIdx < 16 {
				partial[i].L3[partialIdx] = src[idx]
				partialIdx++
				idx++
				length--
			}
		}

		aesMerge(&S0123, &partial[0])
		aesMerge(&S4567, &partial[1])
		aesMerge(&S89AB, &partial[2])
		aesMerge(&SCDEF, &partial[3])
	}

	// combine the 16 streams into a single hash
	// to spread the bits out evenly
	r0 := iv
	aesRotate(&r0, &S0123)
	aesRotate(&r0, &S4567)
	aesRotate(&r0, &S89AB)
	aesRotate(&r0, &SCDEF)

	aesRotate(&r0, &S0123)
	aesRotate(&r0, &S4567)
	aesRotate(&r0, &S89AB)
	aesRotate(&r0, &SCDEF)

	aesRotate(&r0, &S0123)
	aesRotate(&r0, &S4567)
	aesRotate(&r0, &S89AB)
	aesRotate(&r0, &SCDEF)

	aesRotate(&r0, &S0123)
	aesRotate(&r0, &S4567)
	aesRotate(&r0, &S89AB)
	aesRotate(&r0, &SCDEF)

	// repeat AES enough times to ensure diffusion
	// to all bits in each 128-bit lane
	aesMerge(&r0, &iv)
	aesMerge(&r0, &iv)
	aesMerge(&r0, &iv)
	aesMerge(&r0, &iv)
	aesMerge(&r0, &iv)

	return &r0
}

func putUint64(buf []byte, x uint64) {
	i := 0
	for ; x >= 0xFF; i++ {
		buf[i] = byte(x) & 0xFF
		x >>= 8
	}
	buf[i] = byte(x)
}

func aesLoad(s *meowLane, from []byte) {
	aesDecSi128(&s.L0[0], &from[:16][0], &s.L0[0])
	aesDecSi128(&s.L1[0], &from[16:32][0], &s.L1[0])
	aesDecSi128(&s.L2[0], &from[32:48][0], &s.L2[0])
	aesDecSi128(&s.L3[0], &from[48:][0], &s.L3[0])
}

func aesMerge(a, b *meowLane) {
	aesDecSi128(&a.L0[0], &b.L0[0], &a.L0[0])
	aesDecSi128(&a.L1[0], &b.L1[0], &a.L1[0])
	aesDecSi128(&a.L2[0], &b.L2[0], &a.L2[0])
	aesDecSi128(&a.L3[0], &b.L3[0], &a.L3[0])
}

func aesRotate(a, b *meowLane) {
	aesDecSi128(&a.L0[0], &b.L0[0], &a.L0[0])
	aesDecSi128(&a.L1[0], &b.L1[0], &a.L1[0])
	aesDecSi128(&a.L2[0], &b.L2[0], &a.L2[0])
	aesDecSi128(&a.L3[0], &b.L3[0], &a.L3[0])

	b.L0, b.L1, b.L2, b.L3 = b.L1, b.L2, b.L3, b.L0
}
