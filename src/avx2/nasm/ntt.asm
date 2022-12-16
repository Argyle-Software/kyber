%include "shuffle.inc"
%include "consts.inc"

%macro mul 4-8 15,15,2,2
vpmullw		 ymm12,ymm%1,ymm%5
vpmullw		 ymm13,ymm%2,ymm%5

vpmullw		 ymm14,ymm%3,ymm%6
vpmullw		 ymm15,ymm%4,ymm%6

vpmulhw		 ymm%1,ymm%1,ymm%7
vpmulhw		 ymm%2,ymm%2,ymm%7

vpmulhw		 ymm%3,ymm%3,ymm%8
vpmulhw		 ymm%4,ymm%4,ymm%8
%endmacro

%macro reduce 0
vpmulhw		ymm12,ymm12,ymm0
vpmulhw		ymm13,ymm13,ymm0

vpmulhw		ymm14,ymm14,ymm0
vpmulhw		ymm15,ymm15,ymm0
%endmacro

%macro update 9
vpaddw		 ymm%1,ymm%2,ymm%6
vpsubw		 ymm%6,ymm%2,ymm%6
vpaddw		 ymm%2,ymm%3,ymm%7

vpsubw		 ymm%7,ymm%3,ymm%7
vpaddw		 ymm%3,ymm%4,ymm%8
vpsubw		 ymm%8,ymm%4,ymm%8

vpaddw		 ymm%4,ymm%5,ymm%9
vpsubw		 ymm%9,ymm%5,ymm%9

vpsubw		 ymm%1,ymm%1,ymm12
vpaddw		 ymm%6,ymm%6,ymm12
vpsubw		 ymm%2,ymm%2,ymm13

vpaddw		 ymm%7,ymm%7,ymm13
vpsubw		 ymm%3,ymm%3,ymm14
vpaddw		 ymm%8,ymm%8,ymm14

vpsubw		 ymm%4,ymm%4,ymm15
vpaddw		 ymm%9,ymm%9,ymm15
%endmacro

%macro level0 1
vpbroadcastq		ymm15,[rsi+ (_ZETAS_EXP+0)*2]
vmovdqa		 ymm8,[rdi + (64*%1+  128)*2]
vmovdqa		 ymm9,[rdi + (64*%1+  144)*2]
vmovdqa		 ymm10,[rdi + (64*%1+  160)*2]
vmovdqa		 ymm11,[rdi + (64*%1+  176)*2]
vpbroadcastq		ymm2,[rsi+ (_ZETAS_EXP+4)*2]

mul		8,9,10,11

vmovdqa		 ymm4,[rdi + (64*%1+    0)*2]
vmovdqa		 ymm5,[rdi + (64*%1+   16)*2]
vmovdqa		 ymm6,[rdi + (64*%1+   32)*2]
vmovdqa		 ymm7,[rdi + (64*%1+   48)*2]

reduce
update		3,4,5,6,7,8,9,10,11

vmovdqa		[rdi + (64*%1+   0)*2],ymm3
vmovdqa		[rdi + (64*%1+  16)*2],ymm4
vmovdqa		[rdi + (64*%1+  32)*2],ymm5
vmovdqa		[rdi + (64*%1+  48)*2],ymm6
vmovdqa		[rdi + (64*%1+ 128)*2],ymm8
vmovdqa		[rdi + (64*%1+ 144)*2],ymm9
vmovdqa		[rdi + (64*%1+ 160)*2],ymm10
vmovdqa		[rdi + (64*%1+ 176)*2],ymm11
%endmacro

%macro levels1t6 1
;  level 1
vmovdqa		ymm15,[rsi+ (_ZETAS_EXP+224*%1+16)*2]
vmovdqa		ymm8,[rdi + (128*%1+ 64)*2]
vmovdqa		ymm9,[rdi + (128*%1+ 80)*2]
vmovdqa		ymm10,[rdi + (128*%1+ 96)*2]
vmovdqa		ymm11,[rdi + (128*%1+ 112)*2]
vmovdqa		ymm2,[rsi+ (_ZETAS_EXP+224*%1+32)*2]

mul		8,9,10,11

vmovdqa		ymm4,[rdi + (128*%1+ 0)*2]
vmovdqa		ymm5,[rdi + (128*%1+ 16)*2]
vmovdqa		ymm6,[rdi + (128*%1+ 32)*2]
vmovdqa		ymm7,[rdi + (128*%1+ 48)*2]

reduce
update		3,4,5,6,7,8,9,10,11

;  level 2
shuffle8	5,10,7,10
shuffle8	6,11,5,11

vmovdqa		ymm15,[rsi+ (_ZETAS_EXP+224*%1+48)*2]
vmovdqa		ymm2,[rsi+ (_ZETAS_EXP+224*%1+64)*2]

mul		7,10,5,11

shuffle8	3,8,6,8
shuffle8	4,9,3,9

reduce
update		4,6,8,3,9,7,10,5,11

;  level 3
shuffle4	8,5,9,5
shuffle4	3,11,8,11

vmovdqa		ymm15,[rsi+ (_ZETAS_EXP+224*%1+80)*2]
vmovdqa		ymm2,[rsi+ (_ZETAS_EXP+224*%1+96)*2]

mul		9,5,8,11

shuffle4	4,7,3,7
shuffle4	6,10,4,10

reduce
update		6,3,7,4,10,9,5,8,11

;  level 4
shuffle2	7,8,10,8
shuffle2	4,11,7,11

vmovdqa		ymm15,[rsi+ (_ZETAS_EXP+224*%1+112)*2]
vmovdqa		ymm2,[rsi+ (_ZETAS_EXP+224*%1+128)*2]

mul		10,8,7,11

shuffle2	6,9,4,9
shuffle2	3,5,6,5

reduce
update		3,4,9,6,5,10,8,7,11

;  level 5
shuffle1	9,7,5,7
shuffle1	6,11,9,11

vmovdqa		ymm15,[rsi+ (_ZETAS_EXP+224*%1+144)*2]
vmovdqa		ymm2,[rsi+ (_ZETAS_EXP+224*%1+160)*2]

mul		5,7,9,11

shuffle1	3,10,6,10
shuffle1	4,8,3,8

reduce
update		4,6,10,3,8,5,7,9,11

;  level 6
vmovdqa		ymm14,[rsi+ (_ZETAS_EXP+224*%1+176)*2]
vmovdqa		ymm15,[rsi+ (_ZETAS_EXP+224*%1+208)*2]
vmovdqa		ymm8,[rsi+ (_ZETAS_EXP+224*%1+192)*2]
vmovdqa		ymm2,[rsi+ (_ZETAS_EXP+224*%1+224)*2]

mul		10,3,9,11,14,15,8,2

reduce
update		8,4,6,5,7,10,3,9,11

vmovdqa		[rdi + (128*%1+ 0)*2],ymm8
vmovdqa		[rdi + (128*%1+ 16)*2],ymm4
vmovdqa		[rdi + (128*%1+ 32)*2],ymm10
vmovdqa		[rdi + (128*%1+ 48)*2],ymm3
vmovdqa		[rdi + (128*%1+ 64)*2],ymm6
vmovdqa		[rdi + (128*%1+ 80)*2],ymm5
vmovdqa		[rdi + (128*%1+ 96)*2],ymm9
vmovdqa		[rdi + (128*%1+ 112)*2],ymm11
%endmacro

SECTION .text
global ntt_avx
global _ntt_avx
ntt_avx:
_ntt_avx:
vmovdqa		ymm0,[rsi + _16XQ*2]

level0		0
level0		1

levels1t6	0
levels1t6	1

ret
