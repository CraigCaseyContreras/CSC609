#
# makefile for proj2, csc507/609 term 201
# author: bjr
# date: sep 2019
#


PY= python3
#PY= python2

VERBOSE= 
#VERBOSE= -v

N_TRIALS= 1000
KEY= bca

AIV = adv-indistin-vign
AIE = adv-indistin-enig

all:
	make encryption-tests
	make ${AIV}
	make ${AIE}

${AIV}:
	${PY} ${AIV}.py ${VERBOSE} ${N_TRIALS}

${AIE}:
	${PY} ${AIE}.py ${VERBOSE} ${N_TRIALS}


encryption-tests:
	${PY} ${AIV}.py -v -k ${KEY} helloworld
	${PY} ${AIE}.py -v -k ${KEY} aaaaaaaaaa

