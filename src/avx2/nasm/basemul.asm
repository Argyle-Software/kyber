%include "consts.inc"

%macro schoolbook 1
vmovdqa		ymm0,[rcx + _16XQINV*2]
vmovdqa		ymm1,[rsi + (64*%1+ 0)*2]		; a0
vmovdqa		ymm2,[rsi + (64*%1+16)*2]		; b0
vmovdqa		ymm3,[rsi + (64*%1+32)*2]		; a1
vmovdqa		ymm4,[rsi + (64*%1+48)*2]		; b1

vpmullw		ymm9,ymm1,ymm0			; a0.lo
vpmullw		ymm10,ymm2,ymm0			; b0.lo
vpmullw		ymm11,ymm3,ymm0			; a1.lo
vpmullw		ymm12,ymm4,ymm0			; b1.lo

vmovdqa		 ymm5,[rdx + (64*%1+   0)*2]		; c0
vmovdqa		 ymm6,[rdx + (64*%1+  16)*2]		; d0

vpmulhw		ymm13,ymm1,ymm5			; a0c0.hi
vpmulhw		ymm1,ymm1,ymm6			; a0d0.hi
vpmulhw		ymm14,ymm2,ymm5			; b0c0.hi
vpmulhw		ymm2,ymm2,ymm6			; b0d0.hi

vmovdqa		 ymm7,[rdx + (64*%1+  32)*2]		; c1
vmovdqa		 ymm8,[rdx + (64*%1+  48)*2]		; d1

vpmulhw		ymm15,ymm3,ymm7			; a1c1.hi
vpmulhw		ymm3,ymm3,ymm8			; a1d1.hi
vpmulhw		ymm0,ymm4,ymm7			; b1c1.hi
vpmulhw		ymm4,ymm4,ymm8			; b1d1.hi

vmovdqa		[rsp],ymm13

vpmullw		ymm13,ymm9,ymm5			; a0c0.lo
vpmullw		ymm9,ymm9,ymm6			; a0d0.lo
vpmullw		ymm5,ymm10,ymm5			; b0c0.lo
vpmullw		ymm10,ymm10,ymm6			; b0d0.lo

vpmullw		ymm6,ymm11,ymm7			; a1c1.lo
vpmullw		ymm11,ymm11,ymm8			; a1d1.lo
vpmullw		ymm7,ymm12,ymm7			; b1c1.lo
vpmullw		ymm12,ymm12,ymm8			; b1d1.lo

vmovdqa		ymm8,[rcx + _16XQ*2]
vpmulhw		ymm13,ymm13,ymm8
vpmulhw		ymm9,ymm9,ymm8
vpmulhw		ymm5,ymm5,ymm8
vpmulhw		ymm10,ymm10,ymm8
vpmulhw		ymm6,ymm6,ymm8
vpmulhw		ymm11,ymm11,ymm8
vpmulhw		ymm7,ymm7,ymm8
vpmulhw		ymm12,ymm12,ymm8

vpsubw		ymm13,ymm13,[rsp]			; -a0c0
vpsubw		ymm9,ymm1,ymm9			; a0d0
vpsubw		ymm5,ymm14,ymm5			; b0c0
vpsubw		ymm10,ymm2,ymm10			; b0d0

vpsubw		ymm6,ymm15,ymm6			; a1c1
vpsubw		ymm11,ymm3,ymm11			; a1d1
vpsubw		ymm7,ymm0,ymm7			; b1c1
vpsubw		ymm12,ymm4,ymm12			; b1d1

vmovdqa		ymm0,[r9]
vmovdqa		ymm1,[r9 + 32]
vpmullw		ymm2,ymm10,ymm0
vpmullw		ymm3,ymm12,ymm0
vpmulhw		ymm10,ymm10,ymm1
vpmulhw		ymm12,ymm12,ymm1
vpmulhw		ymm2,ymm2,ymm8
vpmulhw		ymm3,ymm3,ymm8
vpsubw		ymm10,ymm10,ymm2			; rb0d0
vpsubw		ymm12,ymm12,ymm3			; rb1d1

vpaddw		ymm9,ymm9,ymm5
vpaddw		ymm11,ymm11,ymm7
vpsubw		ymm13,ymm10,ymm13
vpsubw		ymm6,ymm6,ymm12

vmovdqa		[rdi + (64*%1+  0)*2],ymm13
vmovdqa		[rdi + (64*%1+ 16)*2],ymm9
vmovdqa		[rdi + (64*%1+ 32)*2],ymm6
vmovdqa		[rdi + (64*%1+ 48)*2],ymm11
%endmacro

SECTION .text
global basemul_avx
global _basemul_avx
basemul_avx:
_basemul_avx:
mov		r8,rsp
and		rsp,-32
sub		rsp,32

lea		r9,[rcx + (_ZETAS_EXP+176)*2]
schoolbook	0

add		r9,32*2
schoolbook	1

add		r9,192*2
schoolbook	2

add		r9,32*2
schoolbook	3

mov		rsp,r8
ret
