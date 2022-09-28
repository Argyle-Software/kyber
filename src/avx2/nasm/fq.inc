%macro red16 1
vpmulhw   ymm12,ymm%1,ymm1
vpsraw    ymm12,ymm12,10
vpmullw   ymm12,ymm12,ymm0
vpsubw    ymm%1,ymm%1,ymm12
%endmacro

%macro csubq 2
vpsubw    ymm%1,ymm%1,ymm0
vpsraw    ymm%2,ymm%1,15
vpand     ymm%2,ymm%2,ymm0
vpaddw    ymm%1,ymm%1,ymm%2
%endmacro

%macro fqmulprecomp 3-4 12
vpmullw   ymm%4,ymm%3,ymm%1
vpmulhw   ymm%3,ymm%3,ymm%2
vpmulhw   ymm%4,ymm%4,ymm0
vpsubw    ymm%3,ymm%3,ymm%4
%endmacro
