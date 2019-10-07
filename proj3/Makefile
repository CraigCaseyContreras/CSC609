#
# makefile for csc507/609 semester 201
# author: bjr
# date: 24 sep 2019
#

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
	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} ${PWD} > encrypt.out
	@cat encrypt.out | hexdump -C
	cat encrypt.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -d ${PWD} > decrypt.out
	@cat decrypt.out | hexdump -C
	make clean

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "zero" ${PWD} > encrypt_cbc_zero.out
	@cat encrypt_cbc_zero.out | hexdump -C
	cat encrypt_cbc_zero.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "zero" -d ${PWD} > decrypt_cbc_zero.out
	@cat decrypt_cbc_zero.out | hexdump -C

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "pkcs" ${PWD} > encrypt_cbc_pkcs7.out
	@cat encrypt_cbc_pkcs7.out | hexdump -C
	cat encrypt_cbc_pkcs7.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "pkcs" -d ${PWD} > decrypt_cbc_pkcs7.out
	@cat decrypt_cbc_pkcs7.out | hexdump -C

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "iso" ${PWD} > encrypt_cbc_iso.out
	@cat encrypt_cbc_iso.out | hexdump -C
	cat encrypt_cbc_iso.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "iso" -d ${PWD} > decrypt_cbc_iso.out
	@cat decrypt_cbc_iso.out | hexdump -C



	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "zero" ${PWD} > encrypt_ofb_zero.out
	@cat encrypt_ofb_zero.out | hexdump -C
	cat encrypt_ofb_zero.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "zero" -d ${PWD} > decrypt_ofb_zero.out
	@cat decrypt_ofb_zero.out | hexdump -C

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "pkcs" ${PWD} > encrypt_ofb_pkcs7.out
	@cat encrypt_ofb_pkcs7.out | hexdump -C
	cat encrypt_ofb_pkcs7.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "pkcs" -d ${PWD} > decrypt_ofb_pkcs7.out
	@cat decrypt_ofb_pkcs7.out | hexdump -C

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "iso" ${PWD} > encrypt_ofb_iso.out
	@cat encrypt_ofb_iso.out | hexdump -C
	cat encrypt_ofb_iso.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ecb" -p "iso" -d ${PWD} > decrypt_ofb_iso.out
	@cat decrypt_ofb_iso.out | hexdump -C



	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "zero" ${PWD} > encrypt_ebc_zero.out
	@cat encrypt_ebc_zero.out | hexdump -C
	cat encrypt_ebc_zero.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "zero" -d ${PWD} > decrypt_ebc_zero.out
	@cat decrypt_ebc_zero.out | hexdump -C

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "pkcs" ${PWD} > encrypt_ebc_pkcs7.out
	@cat encrypt_ebc_pkcs7.out | hexdump -C
	cat encrypt_ebc_pkcs7.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "pkcs" -d ${PWD} > decrypt_ebc_pkcs7.out
	@cat decrypt_ebc_pkcs7.out | hexdump -C

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "iso" ${PWD} > encrypt_ebc_iso.out
	@cat encrypt_ebc_iso.out | hexdump -C
	cat encrypt_ebc_iso.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "iso" -d ${PWD} > decrypt_ebc_iso.out
	@cat decrypt_ebc_iso.out | hexdump -C


	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "zero" ${PWD} > encrypt_cntr_zero.out
	@cat encrypt_cntr_zero.out | hexdump -C
	cat encrypt_cntr_zero.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "zero" -d ${PWD} > decrypt_cntr_zero.out
	@cat decrypt_cntr_zero.out | hexdump -C

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "pkcs" ${PWD} > encrypt_cntr_pkcs7.out
	@cat encrypt_cntr_pkcs7.out | hexdump -C
	cat encrypt_cntr_pkcs7.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "pkcs" -d ${PWD} > decrypt_cntr_pkcs7.out
	@cat decrypt_cntr_pkcs7.out | hexdump -C

	echo "hello world here i come to destroy you" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "iso" ${PWD} > encrypt_cntr_iso.out
	@cat encrypt_cntr_iso.out | hexdump -C
	cat encrypt_cntr_iso.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cntr" -p "iso" -d ${PWD} > decrypt_cntr_iso.out
	@cat decrypt_cntr_iso.out | hexdump -C

		echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "zero" ${PWD} > encrypt_ebc_zero.out
	@cat encrypt_ebc_zero.out | hexdump -C
	cat encrypt_ebc_zero.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "zero" -d ${PWD} > decrypt_ebc_zero.out
	@cat decrypt_ebc_zero.out | hexdump -C

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "pkcs" ${PWD} > encrypt_ebc_pkcs7.out
	@cat encrypt_ebc_pkcs7.out | hexdump -C
	cat encrypt_ebc_pkcs7.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "pkcs" -d ${PWD} > decrypt_ebc_pkcs7.out
	@cat decrypt_ebc_pkcs7.out | hexdump -C

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "iso" ${PWD} > encrypt_ebc_iso.out
	@cat encrypt_ebc_iso.out | hexdump -C
	cat encrypt_ebc_iso.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "cbc" -p "iso" -d ${PWD} > decrypt_ebc_iso.out
	@cat decrypt_ebc_iso.out | hexdump -C


	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "zero" ${PWD} > encrypt_ofb_zero.out
	@cat encrypt_ofb_zero.out | hexdump -C
	cat encrypt_ofb_zero.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "zero" -d ${PWD} > decrypt_ofb_zero.out
	@cat decrypt_ofb_zero.out | hexdump -C

	echo "hello world" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "pkcs" ${PWD} > encrypt_ofb_pkcs7.out
	@cat encrypt_ofb_pkcs7.out | hexdump -C
	cat encrypt_ofb_pkcs7.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "pkcs" -d ${PWD} > decrypt_ofb_pkcs7.out
	@cat decrypt_ofb_pkcs7.out | hexdump -C

	echo "hello world here i come to destroy you" | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "iso" ${PWD} > encrypt_ofb_iso.out
	@cat encrypt_ofb_iso.out | hexdump -C
	cat encrypt_ofb_iso.out | ${LIB} ${PY3} ${F3} ${VERBOSE} -m "ofb" -p "iso" -d ${PWD} > decrypt_ofb_iso.out
	@cat decrypt_ofb_iso.out | hexdump -C



help-message:
	${LIB} ${PY3} ${F3} -h

libtest:
	${LIB} ${PY3} ${F1}
	${LIB} ${PY3} ${F2}

clean:
	-rm encrypt.out
