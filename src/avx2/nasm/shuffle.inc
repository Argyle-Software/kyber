%macro shuffle8 4
vperm2i128		 ymm%3,ymm%1,ymm%2,020h
vperm2i128		 ymm%4,ymm%1,ymm%2,031h
%endmacro

%macro shuffle4 4
vpunpcklqdq		 ymm%3,ymm%1,ymm%2
vpunpckhqdq		 ymm%4,ymm%1,ymm%2
%endmacro

%macro shuffle2 4
;vpsllq     ymm%3,ymm%2,32
vmovsldup   ymm%3,ymm%2
vpblendd    ymm%3,ymm%1,ymm%3,0AAh
vpsrlq      ymm%1,ymm%1,32
;vmovshdup  ymm%1,ymm%1
vpblendd    ymm%4,ymm%1,ymm%2,0AAh
%endmacro

%macro shuffle1 4
vpslld      ymm%3,ymm%2,16
vpblendw    ymm%3,ymm%1,ymm%3,0AAh
vpsrld      ymm%1,ymm%1,16
vpblendw    ymm%4,ymm%1,ymm%2,0AAh
%endmacro
