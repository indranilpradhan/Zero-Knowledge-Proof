from random import seed
from random import randint
import hashlib
import Crypto.Util.number
import sys
from Crypto import Random
import random

def convert_string_asciisum(m):
    asc = [ord(c) for c in m]
    return sum(asc)

#generate random temp in the range (1,q-1)
#generate z = g^{temp}
def calculate_z(g,q):
    temp = randint(1,q-1)
    z = (g**temp)%q
    return z

#The provable secure hash function h = (g^{x1}%q)*(z^{x2}%q)%q
def hash_function(x1,x2,g,z,q):
    hash_val = ((g**x1)%q * (z**x2)%q)%q
    return hash_val

def loop_exponent(exponent, nr, r, p):
    while(nr != 1):
        nr = (nr*r)%p
        exponent= exponent+1
    return exponent

def loop_gen(nr, exponent, r, p, g):
    exponent = loop_exponent(exponent, nr, r, p)
    if(exponent == p-1 and exponent != None):
        g.append(r)

def generator(p):
    g = []
    for i in range(1,p):
        r = i
        exponent = 1
        nr = r%p
        loop_gen(nr, exponent, r, p, g)
    return random.choice(g)

def choosing_p():
    n = int(sys.argv[1])
    q = Crypto.Util.number.getPrime(n, randfunc=Random.get_random_bytes)
    return q

#The private key for the signer x is generated in the range (1,g-1)
#Generating public public verification key
#The public verification key is y=g^{x}.
def generating_public_key(g,q):
    x = randint(1,g-1)
    y = (g**x)%q
    return y,x

#Signing the message
#Converting the message into binary stream
#Choose a random k in the range (1,q-1).
#Calculating r=g^{k}.
#Calculating e=H(r || M), where ||  denotes concatenation and r is represented as a bit string.
#Calculating s=k-xe
#The signature is the pair, (s,e)
def digital_signature(m,q,g,x,z):
    M = convert_string_asciisum(m)
    k = randint(1, q-1)
    r = (g**k)%q
    e = (hash_function(r,M, g,z,q))
    s = (k-(x*e))%(q-1)
    return s,e

#Verifying the signature
#Taking the same message and converting it to a bit stream
#Calculating rv =g^{s}y^{e}
#Calculating ev=H(rv ||  M)
def verifier(g,y,q,m,s,e,z):
    M = convert_string_asciisum(m)
    h_s = (g**s)%q
    h_y = (y**e)%q
    rv = (h_s*h_y)%q
    ev = (hash_function(rv,M,g,z,q))
    return ev

#Taking the message
#Generating the prime number q og length n
#Generating the generator g
#Computing Z which will be used for hashing
#generating the public verification key y and private key of the signer x. Th eprivate key x will be used by the signer to sign the message.
#After signing the document, the signature pair is (s,e) which is provided by the signer.
#Verifier calculate the ev by verifying the signature
#compare e and ev if they are equal.
def main():
    m = "aaa"
    q = choosing_p()
    g = generator(q)
    z = calculate_z(g,q)
    y,x = generating_public_key(g,q)
    s,e = digital_signature(m,q,g,x,z)
    ev = verifier(g,y,q,m,s,e,z)
    print("e ",e," ev ",ev)
    if (e == ev):
        print("Matched")
    else:
        print("Not matched")

if __name__ == "__main__":
    main()