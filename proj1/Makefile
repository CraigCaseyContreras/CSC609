#
# makefile for proj1
# author: bjr
# date: 2 feb 2018
#

I= gettysburg.txt
KEY= abc
#VERBOSE= -v
#MF= -f Makefile-class
PY= python

all:
	make ${MF} test-vigenere
	make ${MF} test-ioc
	make ${MF} test-crack

test-vigenere:
	cat $I | ${PY} vigenere.py ${KEY} > vigenere.out
	-diff -w vigenere.out proj1-ref1.txt
	cat proj1-ref1.txt | ${PY} vigenere.py -d ${KEY} > vigenere.out
	-diff -w vigenere.out proj1-ref2.txt
	-rm vigenere.out
	
test-ioc:
	cat proj1-ref1.txt | ${PY} ioc.py  ${VERBOSE} > ioc.out
	cat $I | ${PY} vigenere.py liberty | ${PY} ioc.py ${VERBOSE} >> ioc.out
	cat $I | ${PY} vigenere.py jefferson | ${PY} ioc.py ${VERBOSE} >> ioc.out
	-diff ioc.out proj1-ref3.txt
	-rm ioc.out

test-crack:
	cat proj1-ref1.txt | ${PY}  crack-vigenere.py ${VERBOSE} 3 $I > crack.out
	cat $I | ${PY} vigenere.py liberty | ${PY} crack-vigenere.py ${VERBOSE} 7 $I >> crack.out
	cat $I | ${PY} vigenere.py jefferson | ${PY} crack-vigenere.py ${VERBOSE} 9 $I >> crack.out
	-diff crack.out proj1-ref4.txt
	-rm crack.out 
