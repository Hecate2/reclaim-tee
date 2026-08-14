//go:build amd64 && gc

#include "textflag.h"

// func clmul128(a, b, lo, hi *Label)
//
// Compute the unreduced 256-bit carry-less product using four independent
// 64-bit PCLMUL products. Label limbs use the processor's native polynomial
// bit order, so no byte shuffles are required.
TEXT ·clmul128(SB), NOSPLIT, $0-32
	MOVQ a+0(FP), AX
	MOVOU (AX), X0
	MOVQ b+8(FP), BX
	MOVOU (BX), X1

	MOVO X0, X2
	PCLMULQDQ $0x00, X1, X2
	MOVO X0, X3
	PCLMULQDQ $0x01, X1, X3
	MOVO X0, X4
	PCLMULQDQ $0x10, X1, X4
	MOVO X0, X5
	PCLMULQDQ $0x11, X1, X5

	PXOR X4, X3
	MOVO X3, X6
	PSLLDQ $8, X6
	PXOR X6, X2
	PSRLDQ $8, X3
	PXOR X3, X5

	MOVQ lo+16(FP), CX
	MOVOU X2, (CX)
	MOVQ hi+24(FP), DX
	MOVOU X5, (DX)
	RET

