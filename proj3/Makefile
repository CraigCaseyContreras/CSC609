#
# makefile for csc507/609 semester 201
# author: bjr
# date: 24 sep 2019
#

	#echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} ${PWD} > encrypt.out
	#echo "hello" | ${LIB} ${PY3} ${F3} ${VERBOSE} ${PWD} > encrypt.out
	#echo "hello world yes!" | ${LIB} ${PY3} ${F3} ${VERBOSE} ${PWD} > encrypt.out
	#echo "hello world yes! no!" | ${LIB} ${PY3} ${F3} ${VERBOSE} ${PWD} > encrypt.out
	#echo "hello world i am craig contreras!!!!!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} ${PWD} > encrypt.out
	#echo "" | ${LIB} ${PY3} ${F3} ${VERBOSE} ${PWD} > encrypt.out

LIB= PYTHONPATH="../class/modules"
PY3= python
#VERBOSE= -v
VERBOSE=

F1= blowfish_test.py
F2= rijndael_test.py
F3= encrypt.py

PWD= "the key phrase" 

all:
	make run

run:

	echo "hello world i am craig contreras hahaha!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean

	echo "hello world i am craig contreras hahaha!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "zero" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "zero" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean

	echo "hello world i am craig contreras hahaha!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "pkcs" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "pkcs" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean
	
	echo "hello world i am craig contreras hahaha!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "iso" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "iso" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean



	echo "hello world I am craig contreras!!!!!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "zero" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "zero" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean

	echo "hello world I am craig contreras!!!!!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "pkcs" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "pkcs" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean
	
	echo "hello world I am craig contreras!!!!!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "iso" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "iso" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean


	echo "hello world I am craig contreras!!!!!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "zero" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "zero" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean

	echo "hello world I am craig contreras!!!!!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "pkcs" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "pkcs" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean
	
	echo "hello world I am craig contreras!!!!!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "iso" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "iso" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean

	echo "hello world I am craig contreras!!!!!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "zero" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "zero" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean

	echo "hello world I am craig contreras!!!!!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "pkcs" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "pkcs" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean
	
	echo "hello world i am craig contreras!!!!!!!!" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "iso" ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "iso" -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean



help-message:
	${LIB} ${PY3} ${F3} -h

libtest:
	${LIB} ${PY3} ${F1}
	${LIB} ${PY3} ${F2}

clean:
	-rm encrypt.out
	-rm decrypt.out
