%include "fq.inc"
%include "shuffle.inc"
%include "consts.inc"

SECTION .text
nttunpack128_avx:
;load
vmovdqa		ymm4,[rdi]
vmovdqa		ymm5,[rdi + 32]
vmovdqa		ymm6,[rdi + 64]
vmovdqa		ymm7,[rdi + 96]
vmovdqa		ymm8,[rdi + 128]
vmovdqa		ymm9,[rdi + 160]
vmovdqa		ymm10,[rdi + 192]
vmovdqa		ymm11,[rdi + 224]

shuffle8	4,8,3,8
shuffle8	5,9,4,9
shuffle8	6,10,5,10
shuffle8	7,11,6,11

shuffle4	3,5,7,5
shuffle4	8,10,3,10
shuffle4	4,6,8,6
shuffle4	9,11,4,11

shuffle2	7,8,9,8
shuffle2	5,6,7,6
shuffle2	3,4,5,4
shuffle2	10,11,3,11

shuffle1	9,5,10,5
shuffle1	8,4,9,4
shuffle1	7,3,8,3
shuffle1	6,11,7,11

;store
vmovdqa		[rdi],ymm10
vmovdqa		[rdi + 32],ymm5
vmovdqa		[rdi + 64],ymm9
vmovdqa		[rdi + 96],ymm4
vmovdqa		[rdi + 128],ymm8
vmovdqa		[rdi + 160],ymm3
vmovdqa		[rdi + 192],ymm7
vmovdqa		[rdi + 224],ymm11

ret

global nttunpack_avx
global _nttunpack_avx
nttunpack_avx:
_nttunpack_avx:
call		nttunpack128_avx
add		rdi,256
call		nttunpack128_avx
ret

ntttobytes128_avx:
;load
vmovdqa		ymm5,[rsi]
vmovdqa		ymm6,[rsi + 32]
vmovdqa		ymm7,[rsi + 64]
vmovdqa		ymm8,[rsi + 96]
vmovdqa		ymm9,[rsi + 128]
vmovdqa		ymm10,[rsi + 160]
vmovdqa		ymm11,[rsi + 192]
vmovdqa		ymm12,[rsi + 224]

;csubq
csubq		5,13
csubq		6,13
csubq		7,13
csubq		8,13
csubq		9,13
csubq		10,13
csubq		11,13
csubq		12,13

;bitpack
vpsllw		 ymm4,ymm6,12
vpor		ymm4,ymm5,ymm4

vpsrlw		 ymm5,ymm6,4
vpsllw		 ymm6,ymm7,8
vpor		ymm5,ymm6,ymm5

vpsrlw		 ymm6,ymm7,8
vpsllw		 ymm7,ymm8,4
vpor		ymm6,ymm7,ymm6

vpsllw		 ymm7,ymm10,12
vpor		ymm7,ymm9,ymm7

vpsrlw		 ymm8,ymm10,4
vpsllw		 ymm9,ymm11,8
vpor		ymm8,ymm9,ymm8

vpsrlw		 ymm9,ymm11,8
vpsllw		 ymm10,ymm12,4
vpor		ymm9,ymm10,ymm9

shuffle1	4,5,3,5
shuffle1	6,7,4,7
shuffle1	8,9,6,9

shuffle2	3,4,8,4
shuffle2	6,5,3,5
shuffle2	7,9,6,9

shuffle4	8,3,7,3
shuffle4	6,4,8,4
shuffle4	5,9,6,9

shuffle8	7,8,5,8
shuffle8	6,3,7,3
shuffle8	4,9,6,9

;store
vmovdqu		[rdi],ymm5
vmovdqu		[rdi + 32],ymm7
vmovdqu		[rdi + 64],ymm6
vmovdqu		[rdi + 96],ymm8
vmovdqu		[rdi + 128],ymm3
vmovdqu		[rdi + 160],ymm9

ret

global ntttobytes_avx
global _ntttobytes_avx
ntttobytes_avx:
_ntttobytes_avx:
;consts
vmovdqa		ymm0,[rdx + _16XQ*2]
call		ntttobytes128_avx
add		rsi,256
add		rdi,192
call		ntttobytes128_avx
ret

nttfrombytes128_avx:
;load
vmovdqu		ymm4,[rsi]
vmovdqu		ymm5,[rsi + 32]
vmovdqu		ymm6,[rsi + 64]
vmovdqu		ymm7,[rsi + 96]
vmovdqu		ymm8,[rsi + 128]
vmovdqu		ymm9,[rsi + 160]

shuffle8	4,7,3,7
shuffle8	5,8,4,8
shuffle8	6,9,5,9

shuffle4	3,8,6,8
shuffle4	7,5,3,5
shuffle4	4,9,7,9

shuffle2	6,5,4,5
shuffle2	8,7,6,7
shuffle2	3,9,8,9

shuffle1	4,7,10,7
shuffle1	5,8,4,8
shuffle1	6,9,5,9

;bitunpack
vpsrlw		 ymm11,ymm10,12
vpsllw		 ymm12,ymm7,4
vpor		ymm11,ymm12,ymm11
vpand		ymm10,ymm10,ymm0
vpand		ymm11,ymm11,ymm0

vpsrlw		 ymm12,ymm7,8
vpsllw		 ymm13,ymm4,8
vpor		ymm12,ymm13,ymm12
vpand		ymm12,ymm12,ymm0

vpsrlw		 ymm13,ymm4,4
vpand		ymm13,ymm13,ymm0

vpsrlw		 ymm14,ymm8,12
vpsllw		 ymm15,ymm5,4
vpor		ymm14,ymm15,ymm14
vpand		ymm8,ymm8,ymm0
vpand		ymm14,ymm14,ymm0

vpsrlw		 ymm15,ymm5,8
vpsllw		 ymm1,ymm9,8
vpor		ymm15,ymm1,ymm15
vpand		ymm15,ymm15,ymm0

vpsrlw		 ymm1,ymm9,4
vpand		ymm1,ymm1,ymm0

;store
vmovdqa		[rdi],ymm10
vmovdqa		[rdi + 32],ymm11
vmovdqa		[rdi + 64],ymm12
vmovdqa		[rdi + 96],ymm13
vmovdqa		[rdi + 128],ymm8
vmovdqa		[rdi + 160],ymm14
vmovdqa		[rdi + 192],ymm15
vmovdqa		[rdi + 224],ymm1

ret

global nttfrombytes_avx
global _nttfrombytes_avx
nttfrombytes_avx:
_nttfrombytes_avx:
;consts
vmovdqa		ymm0,[rdx + _16XMASK*2]
call		nttfrombytes128_avx
add		rdi,256
add		rsi,192
call		nttfrombytes128_avx
ret
