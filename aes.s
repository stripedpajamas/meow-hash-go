#include "textflag.h"

// func aesDecSi128(a, b, dst *byte)
TEXT ·aesDecSi128(SB),NOSPLIT,$0
	MOVQ a+0(FP), AX
	MOVQ b+8(FP), BX
	MOVQ dst+16(FP), DX
	MOVUPS 0(AX), X1
	MOVUPS 0(BX), X0
	AESDEC X0, X1
	MOVUPS X1, 0(DX)
	RET
