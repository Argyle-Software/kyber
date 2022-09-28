%include "fq.inc"
%include "consts.inc"

SECTION .text
reduce128_avx:
;load
vmovdqa		ymm2,[rdi]
vmovdqa		ymm3,[rdi + 32]
vmovdqa		ymm4,[rdi + 64]
vmovdqa		ymm5,[rdi + 96]
vmovdqa		ymm6,[rdi + 128]
vmovdqa		ymm7,[rdi + 160]
vmovdqa		ymm8,[rdi + 192]
vmovdqa		ymm9,[rdi + 224]

red16		2
red16		3
red16		4
red16		5
red16		6
red16		7
red16		8
red16		9

;store
vmovdqa		[rdi],ymm2
vmovdqa		[rdi + 32],ymm3
vmovdqa		[rdi + 64],ymm4
vmovdqa		[rdi + 96],ymm5
vmovdqa		[rdi + 128],ymm6
vmovdqa		[rdi + 160],ymm7
vmovdqa		[rdi + 192],ymm8
vmovdqa		[rdi + 224],ymm9

ret

global reduce_avx
global _reduce_avx
reduce_avx:
_reduce_avx:
;consts
vmovdqa		ymm0,[rsi + _16XQ*2]
vmovdqa		ymm1,[rsi + _16XV*2]
call		reduce128_avx
add		rdi,256
call		reduce128_avx
ret

tomont128_avx:
;load
vmovdqa		ymm3,[rdi]
vmovdqa		ymm4,[rdi + 32]
vmovdqa		ymm5,[rdi + 64]
vmovdqa		ymm6,[rdi + 96]
vmovdqa		ymm7,[rdi + 128]
vmovdqa		ymm8,[rdi + 160]
vmovdqa		ymm9,[rdi + 192]
vmovdqa		ymm10,[rdi + 224]

fqmulprecomp	1,2,3,11
fqmulprecomp	1,2,4,12
fqmulprecomp	1,2,5,13
fqmulprecomp	1,2,6,14
fqmulprecomp	1,2,7,15
fqmulprecomp	1,2,8,11
fqmulprecomp	1,2,9,12
fqmulprecomp	1,2,10,13

;store
vmovdqa		[rdi],ymm3
vmovdqa		[rdi + 32],ymm4
vmovdqa		[rdi + 64],ymm5
vmovdqa		[rdi + 96],ymm6
vmovdqa		[rdi + 128],ymm7
vmovdqa		[rdi + 160],ymm8
vmovdqa		[rdi + 192],ymm9
vmovdqa		[rdi + 224],ymm10

ret

global tomont_avx
global _tomont_avx
tomont_avx:
_tomont_avx:
;consts
vmovdqa		ymm0,[rsi + _16XQ*2]
vmovdqa		ymm1,[rsi + _16XMONTSQLO*2]
vmovdqa		ymm2,[rsi + _16XMONTSQHI*2]
call		tomont128_avx
add		rdi,256
call		tomont128_avx
ret
