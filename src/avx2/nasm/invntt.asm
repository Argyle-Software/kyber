%include "shuffle.inc"
%include "fq.inc"
%include "consts.inc"

%macro butterfly 8-12 2,2,3,3
vpsubw   ymm12,ymm%5,ymm%1
vpaddw   ymm%1,ymm%1,ymm%5
vpsubw   ymm13,ymm%6,ymm%2

vpmullw   ymm%5,ymm12,ymm%9
vpaddw    ymm%2,ymm%2,ymm%6
vpsubw    ymm14,ymm%7,ymm%3

vpmullw   ymm%6,ymm13,ymm%9
vpaddw    ymm%3,ymm%3,ymm%7
vpsubw    ymm15,ymm%8,ymm%4

vpmullw   ymm%7,ymm14,ymm%10
vpaddw    ymm%4,ymm%4,ymm%8
vpmullw   ymm%8,ymm15,ymm%10

vpmulhw   ymm12,ymm12,ymm%11
vpmulhw   ymm13,ymm13,ymm%11

vpmulhw   ymm14,ymm14,ymm%12
vpmulhw   ymm15,ymm15,ymm%12

vpmulhw   ymm%5,ymm%5,ymm0

vpmulhw   ymm%6,ymm%6,ymm0

vpmulhw   ymm%7,ymm%7,ymm0
vpmulhw   ymm%8,ymm%8,ymm0

vpsubw    ymm%5,ymm12,ymm%5

vpsubw    ymm%6,ymm13,ymm%6

vpsubw    ymm%7,ymm14,ymm%7
vpsubw    ymm%8,ymm15,ymm%8
%endmacro

%macro intt_levels0t5 1
;  level 0 
vmovdqa   ymm2,[rsi + _16XFLO*2]
vmovdqa   ymm3,[rsi + _16XFHI*2]

vmovdqa   ymm4,[rdi + (128*%1+  0)*2]
vmovdqa   ymm6,[rdi + (128*%1+  32)*2]
vmovdqa   ymm5,[rdi + (128*%1+  16)*2]
vmovdqa   ymm7,[rdi + (128*%1+  48)*2]

fqmulprecomp  2,3,4
fqmulprecomp  2,3,6
fqmulprecomp  2,3,5
fqmulprecomp  2,3,7

vmovdqa   ymm8,[rdi + (128*%1+  64)*2]
vmovdqa   ymm10,[rdi + (128*%1+  96)*2]
vmovdqa   ymm9,[rdi + (128*%1+  80)*2]
vmovdqa   ymm11,[rdi + (128*%1+  112)*2]

fqmulprecomp  2,3,8
fqmulprecomp  2,3,10
fqmulprecomp  2,3,9
fqmulprecomp  2,3,11

vpermq ymm15,[rsi + (_ZETAS_EXP+(1-%1)*224+208)*2],04Eh
vpermq ymm1,[rsi + (_ZETAS_EXP+(1-%1)*224+176)*2],04Eh
vpermq ymm2,[rsi + (_ZETAS_EXP+(1-%1)*224+224)*2],04Eh
vpermq ymm3,[rsi + (_ZETAS_EXP+(1-%1)*224+192)*2],04Eh
vmovdqa   ymm12,[rsi + _REVIDXB*2]
vpshufb   ymm15,ymm15,ymm12
vpshufb   ymm1,ymm1,ymm12
vpshufb   ymm2,ymm2,ymm12
vpshufb   ymm3,ymm3,ymm12

butterfly  4,5,8,9,6,7,10,11,15,1,2,3

;  level 1 
vpermq ymm2,[rsi + (_ZETAS_EXP+(1-%1)*224+144)*2],04Eh
vpermq ymm3,[rsi + (_ZETAS_EXP+(1-%1)*224+160)*2],04Eh
vmovdqa   ymm1,[rsi + _REVIDXB*2]
vpshufb   ymm2,ymm2,ymm1
vpshufb   ymm3,ymm3,ymm1

butterfly  4,5,6,7,8,9,10,11,2,2,3,3

shuffle1  4,5,3,5
shuffle1  6,7,4,7
shuffle1  8,9,6,9
shuffle1  10,11,8,11

;  level 2 
vmovdqa   ymm12,[rsi + _REVIDXD*2]
vpermd    ymm2,ymm12,[rsi + (_ZETAS_EXP+(1-%1)*224+112)*2]
vpermd    ymm10,ymm12,[rsi + (_ZETAS_EXP+(1-%1)*224+128)*2]

butterfly  3,4,6,8,5,7,9,11,2,2,10,10

vmovdqa    ymm1,[rsi + _16XV*2]
red16    3

shuffle2  3,4,10,4
shuffle2  6,8,3,8
shuffle2  5,7,6,7
shuffle2  9,11,5,11

;  level 3 
vpermq ymm2,[rsi + (_ZETAS_EXP+(1-%1)*224+80)*2],01Bh
vpermq ymm9,[rsi + (_ZETAS_EXP+(1-%1)*224+96)*2],01Bh

butterfly  10,3,6,5,4,8,7,11,2,2,9,9

shuffle4  10,3,9,3
shuffle4  6,5,10,5
shuffle4  4,8,6,8
shuffle4  7,11,4,11

;  level 4 
vpermq ymm2,[rsi + (_ZETAS_EXP+(1-%1)*224+48)*2],04Eh
vpermq ymm7,[rsi + (_ZETAS_EXP+(1-%1)*224+64)*2],04Eh

butterfly 9,10,6,4,3,5,8,11,2,2,7,7

red16    9

shuffle8  9,10,7,10
shuffle8  6,4,9,4
shuffle8  3,5,6,5
shuffle8  8,11,3,11

;  level 5 
vmovdqa    ymm2,[rsi + (_ZETAS_EXP+(1-%1)*224+16)*2]
vmovdqa    ymm8,[rsi + (_ZETAS_EXP+(1-%1)*224+32)*2]

butterfly  7,9,6,3,10,4,5,11,2,2,8,8

vmovdqa    [rdi + (128*%1 + 0)*2],ymm7
vmovdqa    [rdi + (128*%1 + 16)*2],ymm9
vmovdqa    [rdi + (128*%1 + 32)*2],ymm6
vmovdqa    [rdi + (128*%1 + 48)*2],ymm3
vmovdqa    [rdi + (128*%1 + 64)*2],ymm10
vmovdqa    [rdi + (128*%1 + 80)*2],ymm4
vmovdqa    [rdi + (128*%1 + 96)*2],ymm5
vmovdqa    [rdi + (128*%1 + 112)*2],ymm11
%endmacro

%macro intt_level6 1
;  level 6 
vmovdqa       ymm4,[rdi + (64*%1+  0)*2]
vmovdqa       ymm8,[rdi + (64*%1+  128)*2]
vmovdqa       ymm5,[rdi + (64*%1+  16)*2]
vmovdqa       ymm9,[rdi + (64*%1+  144)*2]
vpbroadcastq	ymm2,[rsi + (_ZETAS_EXP+0)*2]

vmovdqa       ymm6,[rdi + (64*%1+  32)*2]
vmovdqa       ymm10,[rdi + (64*%1+  160)*2]
vmovdqa       ymm7,[rdi + (64*%1+  48)*2]
vmovdqa       ymm11,[rdi + (64*%1+  176)*2]
vpbroadcastq  ymm3,[rsi + (_ZETAS_EXP+4)*2]

butterfly 4,5,6,7,8,9,10,11

%if %1 == 0
red16 4
%endif

vmovdqa    [rdi + (64*%1+   0)*2],ymm4
vmovdqa    [rdi + (64*%1+  16)*2],ymm5
vmovdqa    [rdi + (64*%1+  32)*2],ymm6
vmovdqa    [rdi + (64*%1+  48)*2],ymm7
vmovdqa    [rdi + (64*%1+ 128)*2],ymm8
vmovdqa    [rdi + (64*%1+ 144)*2],ymm9
vmovdqa    [rdi + (64*%1+ 160)*2],ymm10
vmovdqa    [rdi + (64*%1+ 176)*2],ymm11
%endmacro

SECTION .text
global invntt_avx
global _invntt_avx
invntt_avx:
_invntt_avx:
vmovdqa   ymm0,[rsi + _16XQ*2]

intt_levels0t5  0
intt_levels0t5  1

intt_level6 0
intt_level6 1
ret
