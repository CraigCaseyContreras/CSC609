#
# makefile for csc507/609 semester 201
# author: bjr
# date: 24 sep 2019
#

#LIB= PYTHONPATH="../../class/modules"
LIB= PYTHONPATH="../modules"
PY3= python3
#VERBOSE= -v
VERBOSE=

F1= blowfish_test.py
F2= rijndael_test.py
F3= encrypt.py

PWD= "the key phrase"

all:
	make run

run:
	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean

help-message:
	${LIB} ${PY3} ${F3} -h

libtest:
	${LIB} ${PY3} ${F1}
	${LIB} ${PY3} ${F2}

# clean:
# 	-rm encrypt.out
