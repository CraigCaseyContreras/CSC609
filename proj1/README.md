Note that the Makefile for crack was wrong. Instead of including the number 9 with jefferson, it included 7. So I simply changed the 7 to 9 and it worked perfectly. Before, there were two number 7's.

Changed from

	cat proj1-ref1.txt | ${PY}  crack-vigenere.py ${VERBOSE} 3 $I > crack.out
	cat $I | ${PY} vigenere.py liberty | ${PY} crack-vigenere.py ${VERBOSE} 7 $I >> crack.out
	cat $I | ${PY} vigenere.py jefferson | ${PY} crack-vigenere.py ${VERBOSE} 7 $I >> crack.out

to 
	cat proj1-ref1.txt | ${PY}  crack-vigenere.py ${VERBOSE} 3 $I > crack.out
	cat $I | ${PY} vigenere.py liberty | ${PY} crack-vigenere.py ${VERBOSE} 7 $I >> crack.out
	cat $I | ${PY} vigenere.py jefferson | ${PY} crack-vigenere.py ${VERBOSE} 9 $I >> crack.out

- Craig
