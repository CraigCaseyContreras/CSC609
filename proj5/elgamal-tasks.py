#
#	elgamal-tasks.py
#	project 5, csc507.201
#	template author: bjr
#	date of template: 17 nov 2019
#
#	--student information--
#	name: Craig Contreras
#	date: December 4, 2019
#	attribution: Victoria, Lucas, Katarzyna, George
#


import math
import time
import random
import binascii


# -------- utility routines ---------------


def extended_gcd(a,b):
	"""
	extended GCD algorithm. recursive.
	returns (d,s,t) where d = s*a+t*b 
	and d = gcd(a,b)
	"""
	assert(
		a>=0 and b>=0 )
	if b==0:
		return (a,1,0)
	(q,r) = divmod(a,b)
	(d,s,t) = extended_gcd(b,r)
	# gcd(a, b) == gcd(b, r) == s*b + t*r == s*b + t*(a - q*b)
	return (d,t,s-q*t)
	
def gcd(a,b):
	return extended_gcd(a,b)[0]

def isqrt(n):
	"""
	https://stackoverflow.com/questions/15390807/integer-square-root-in-python
	"""
	x = n
	y = (x + 1) // 2
	while y < x:
		x = y
		y = (x + n // x) // 2
	# print("int sqrt of {} is {}".format(n,x))
	return x

"""
# this code needs ...
from sympy.ntheory import isprime

def random_prime(k_bytes):
	p_p = random.randint(2,pow(8,k_bytes))
	p_p = 2*p_p + 1 
	while not isprime(p_p):
		p_p += 2
	return p_p

def eg_prime(k,limit=1000):
	for i in range (limit):
		q = random_prime(k)
		p = 2*q+1
		if isprime(p):
			return p
	return None

def eg_primes(a,b):
	egp = []
	for i in range(a,b):
		egp = egp + [eg_prime(i)]
	return egp

"""

def eg_primes(a,b):
	return [ 104723, 392339, 6342179, 19918439, 121707623 , 23962151483, 8631134347439, 
		1333779268829507, 451687306473103487, 
		117463981192809243479, 35942127482371762228847 ]


# ---------ElGamal Class ---------------


class ElGamal:

	GoodPrime = 8631134347439
	Generator = 7
	CarmichaelZero = 561
	
	def __init__(self):
		self.prime = ElGamal.GoodPrime
		self.gen = ElGamal.Generator
		self.secret = ElGamal.CarmichaelZero
		self.public = self.generate_public_key()
		assert( self.is_generator(self.gen) )
		
	def __repr__(self):
		return "class ElGamal:\n\ts={}\n\tP={}\n\tg={}\n\tp={}\n".format(self.secret,
			self.public, self.gen, self.prime, )

	def generate_public_key(self):
		"""
		given the secret key self.secret, returns the value of the public key.
		"""
		gen = self.gen
		secret = self.secret
		prime = self.prime
		
		pub_key = pow(gen, secret, prime)
		return pub_key

	def get_public(self):
		return ( self.public, self.gen, self.prime )

	def set_params(self, secret, gen, prime):
		self.secret, self.gen, self.prime = secret, gen, prime
		self.public = self.generate_public_key()
		assert( self.is_generator(self.gen))

	def gen_random(self):
		return random.randint(self.prime//4,self.prime//2)
	
	def is_generator(self,g):
		"""
		assumes p = 2q+1, so that <g> is either 1, 2, q, or p-1.
		"""
		# check that (p-1) is the smallest positive integer such
		# pow(g,p-1,n)==1. but do it efficiently, given the assumptions
		# about how (p-1) factors
		return True
		
	def encrypt(self, m):
		"""
		given a number m, return a pair which is the ElGamal encryption of m
		"""
		prime = self.prime
		rand_gen = self.gen_random()
		gen = self.gen
		public = self.public
		
		r_a = pow(gen, rand_gen, prime)
		r_b = pow(public, rand_gen, prime)
		r_b = (r_b * m) % prime
		return (r_a, r_b)

	def calc_inverse(self,x):
		"""
		ElGamal decryption might need inverses. If so, implement this function.
		Given an x this function returns y which is the inverse of x mod self.prime
		"""
		prime = self.prime
		y = pow(x, (prime - 2)//2, prime) % prime
		y = (y*y) % prime
		if (prime - 2) % 2 ==0:
			return y
		else:
			return (x*y) % prime
		
		assert( (x*y) % prime == 1)

	def decrypt(self, c):
		"""
		Given an ElGamal encryption c, of format given by the encrypt function, 
		return the decrypted m
		"""
		c1 = c[0]
		c2 = c[1]
		m = pow(c1, (self.prime - self.secret -1), self.prime)
		m = (m*c2) % self.prime
		return m
		#return "the m from encrypt"


# ------------- discret logs -------------------

def big_step_baby_step(w,g,n,verbose=False):
	"""
	Find the log of w base g in the integers mod n using the big-step/baby-step method.
	"""
	n_sqrt = isqrt(n)
	d = {}

	if verbose:
		print("building table ...")
	
	for i in range(n_sqrt):
		d[pow(g,i,n)] = i
	
	try_this = pow(g, n_sqrt*(n-2), n)
	
	for k in range(n_sqrt):
		h = (w * pow(try_this,k,n)) % n
		if h in d:
			return k*n_sqrt + d[h]
			
	if verbose:
		print('building table ...')

	if verbose:
		print("done!")
		print('sorting table ...')
		
	if verbose:
		print('done!')
		print('binary search for match ...')


def d_log(w,g,n):
	"""
	this is a wrapper function for the big & baby step algrithm.
	it first checks if g is a good generator, but only on the assumption
	that n is prime and of the form 2q+1, with q a prime.
	
	Returns a pair, of which the first element is True or False. If False, 
	the second element is a string describing the error. Else the second
	element is the log.
	"""
	if g<2 or g==n-1:
		return (False, "trivial generator")
	if pow(g,(n-1)//2,n)==1:
		return (False, "{} is a quadratic residue mod {}".format(g,n))
	log_w = big_step_baby_step(w,g,n)
	assert(pow(g,log_w,n)==w)
	return (True,log_w)


# ------ test functions ------------


def elgamal_test(trials):

	elgamal = ElGamal()
	for i in range(trials):
		m = random.randint(2,elgamal.get_public()[2])
		c = elgamal.encrypt(m)
		m2 = elgamal.decrypt(c)
		assert(m==m2)
		print("m:{}\nc:{}".format(m,c))
	print(elgamal)
	return True


def discrete_log_test(x, limit):
	success = True
	primes = eg_primes(0,0) 
	for i in range(limit):
		for base in [3,5,7]:
			t = time.time()
			dl = d_log(x,base,primes[i])
			t = time.time()-t
			if (not dl[0]):
				print(dl[1])
			else:
				#check the answer
				assert(pow(base,dl[1],primes[i])==x)
				# and print the result
				print("d_log({}) base {} Mod {} = {} (in {} seconds)".format(
					x,base,primes[i],dl[1],t))


def make_challenge(secret):
	
	def ascii_2_int(a):
		h = binascii.hexlify(a)
		s = str(h,'ascii')
		i = int(s,16)
		return i

	eg = ElGamal()
	eg.set_params(secret,5,1333779268829507)
	
	message = [b'not', b'the', b'message']
	
	ct = [None] * len(message)
	for i in range(len(message)):
		m = ascii_2_int(message[i])
		ct[i] = eg.encrypt(m)

	return ct

def decode_challenge(secret,cipher_text, verbose=False):

	#Help from Lucas - needed to fix this because otherwise, odd length error
	def int_2_ascii(i):
		h = hex(i)[2:]
		if len(h) % 2 ==1:
			h = '0' + h
		a = binascii.unhexlify(h)
		return a	
		
	'''def int_2_ascii(i):
		h = hex(i)
		a = binascii.unhexlify(h[2:])
		return a'''

	ct = cipher_text
	eg = ElGamal()
	eg.set_params(secret,5,1333779268829507)
	if verbose:
		print(eg.get_public())

	message = [None] * len(ct)
	for i in range(len(ct)):
		m_i = eg.decrypt(ct[i])
		message[i] = int_2_ascii(m_i)

	return message


# ------------ run tests ---------------


elgamal_test(10)

# how large can you make limit_on_power
target_log = 17
limit_on_power = 6
discrete_log_test(target_log,limit_on_power)

# the public key is 123
# you need to figure out the secret key
secret = d_log(123, ElGamal().gen, ElGamal().prime)[1]
print('Secret: ', secret)
message = decode_challenge(secret,
		[(879059454310780, 893889137529005), (123475997005350, 1268193986275797), (209827495157778, 790139893489473)])
print('Message: ', message)


# ------------ EOF ------------------


