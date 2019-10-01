import string
import sys
import os
import argparse 
from collections import Counter
from string import ascii_lowercase
from sys import maxsize



#
# ioc.py
#
# author: Craig Contreras
# date: September 9, 2019
# last update:
# template by: bjr aug 2019
#

def get_ic(s):
	n = len(s)
	ic = 0
	if n-1: ic=(1/(float(n)*(n-1)))*(sum([s.count(a)*(s.count(a)-1) for a in set(s)]))
	return ic

def get_possible_key_ls(avg_ic_arr):
    #cpy=avg_ic_arr.copy()
    cpy=list(avg_ic_arr)       
    avg_ic_arr.sort(reverse=True)
    key_ls=cpy.index(avg_ic_arr[1])+2 #cpy.index(avg_ic_arr[0])+2,
    return key_ls

def get_key_len(c):
    avg_ic_arr=[]
    for n in range(2,27):
        ic_sum=0.0
        avg_ic=0.0
        for i in range(n):
            s=""
            for j in range(0,len(c[i:]),n):
                s+=(c[i:][j])
            ic=get_ic(s)
            ic_sum+=ic
        avg_ic=ic_sum/(n-1)
        avg_ic_arr.append(avg_ic)
    pos_key_ls=get_possible_key_ls(avg_ic_arr)
    return pos_key_ls

def parse_args():
        parser = argparse.ArgumentParser(description="Calculate index of coincidence over stdin, writing result to stdout.")
        parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
        return parser.parse_args()

def main(argv):

        global args_g
        args_g = parse_args()

        ## gatmakeher input
        t = ""

        #f = open("gettysburg.txt", "r")
        #if f.mode == "r":
        #      contents = f.read()

        for line in sys.stdin:
               for c in line:
                     if c.isalpha():
                          t += c
        #
        # code
        # 
        key_1 = get_key_len(t)
        if key_1 <= 3:
        	print("3")
        else:
        	print(key_1)

        

main(sys.argv)
