#
# makefile for csc507/609 semester 201
# author: bjr
# date: 22 oct 2019
#


LIB= PYTHONPATH="../modules:../../class/modules"
PY3= python3
#VERBOSE= -v
VERBOSE=

F= padding-attack.py

PWD= "the key phrase" 
HELLO_WORLD= "hello world"
GETTYSBURG= "Now we are engaged in a great civil war,testing whether that nation, or any nation so conceived and so dedicated,can long endure."

RED= \033[0;31m
GREEN= \033[0;32m
NC= \033[0m


all:
	@echo "try: make sanity-check"

sanity-check:
	@echo "***\n*** ${RED}encrypt a short string ${NC}***\n***"	
	echo ${HELLO_WORLD} | ${LIB} ${PY3} ${F} ${VERBOSE} --mode encrypt ${PWD} > encrypt.out
	hexdump -C encrypt.out
	@echo "***\n*** ${RED}decrypting encrypted short string ${NC}***\n***"	
	cat encrypt.out |  ${LIB} ${PY3} ${F} ${VERBOSE} --mode decrypt ${PWD} > decrypt.out
	hexdump -C decrypt.out
	@echo "***\n*** ${RED}test padding oracle of valid padding ${NC}***\n***"	
	cat encrypt.out |  ${LIB} ${PY3} ${F} ${VERBOSE} --mode attack ${PWD}
	@echo "***\n*** ${RED}encrypt with no randomness ${NC}***\n***"	
	echo ${HELLO_WORLD} | ${LIB} ${PY3} ${F} ${VERBOSE} --mode encrypt -R ${PWD} > encrypt.out
	hexdump -C encrypt.out
	@echo "***\n*** ${RED}encrypting with zero padding ${NC}***\n***"	
	echo ${GETTYSBURG} | ${LIB} ${PY3} ${F} ${VERBOSE} --mode encrypt -z ${PWD} > encrypt.out
	hexdump -C encrypt.out
	@echo "***\n*** ${RED}decrypting long string ${NC}***\n***"	
	cat encrypt.out |  ${LIB} ${PY3} ${F} ${VERBOSE} --mode decrypt -z ${PWD} > decrypt.out
	hexdump -C decrypt.out
	@echo "***\n*** ${RED}test padding oracle of invalid padding ${NC}***\n***"	
	cat encrypt.out |  ${LIB} ${PY3} ${F} ${VERBOSE} --mode attack ${PWD} 
		
clean:
	-rm encrypt.out decrypt.out
