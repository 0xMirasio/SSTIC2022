import base64

P = 0xb73cf44702000000 #taps in LFSR
Debug = True
GF2.<x> = GF(2)[]
K = GF(2^64);

C = Integer(0x0000006e6f6e6101) # entry of LFSR
K1= Integer(0x000000000000007b) # key1
K2= Integer(0x00000000000001c8) # key2

C_bf = K._cache.fetch_int(C)
k2_bf = K._cache.fetch_int(K2)
k1_bf = K._cache.fetch_int(K1)

R_bf = C_bf * k1_bf
R1 = R_bf.integer_representation()
R_bf = R_bf * k1_bf
R2 = R_bf.integer_representation()

R_bf = R_bf + k2_bf
R3 = R_bf.integer_representation()

R_bf = R_bf * k1_bf
R4 = R_bf.integer_representation()

if (Debug):
    print("LFSR(ENTRY,K1) = ",hex(R1)) #second LFSR crypt key2
    print("LFSR(C1,K1) = ",hex(R2)) #second LFSR crypt key2
    print("XOR(C2,k2) = ",hex(R3)) #xor key2
    print("LFSR(C3,k2) = ",hex(R4)) #third lfsr crypt key1
# find k1 with solving equation : ((k1^2 * Entry1 )^ k2) * k1 = Output2
# => ((k1^2 * Entry1 )^ k2) * k1 = Output2
# => k1³ (entry1 - entry2) = output1 - output2


#
a21 = Integer(0xee89f7c16d602ee4) #output1
a21_ = K._cache.fetch_int(a21)
a22 = Integer(0x7baaab8fbc25fca6) #output2
a22_ = K._cache.fetch_int(a22)
a11 = Integer(0x0000006e6f6e6101) #entry1
a11_ = K._cache.fetch_int(a11)
a12 = Integer(0x6f6d796e6f6e6101) #entry2
a12_ = K._cache.fetch_int(a12)


a21ma22 = a21_ + a22_
R = a21ma22.integer_representation()
a11ma12 = a11_ + a12_
R2 = a11ma12.integer_representation()



print("a11-a12 = ",hex(R2))
print("a21-a22 = ",hex(R))

R0 = a21ma22 / a11ma12
R3 = R0.integer_representation()
print(hex(R3))


k1 = R0.nth_root(3, all=True) 

    
#(a11*k1² + k2)*k1 = a21
#(a11*k1² + k2) = a21/k1
# k2 = a21/k1 - a11 * k1²

#(a11*k1² + k2)*k1 = a21
#(a11*k1² + k2) = a21/k1
# k2 = a21/k1 - a11 * k1²
print()
for v in k1:
    a21dk1 = (a21_ / v)
    a = a21dk1.integer_representation()
    a11k1carre = a11_ * v * v
    a = a11k1carre.integer_representation()
    
    k2 = a21dk1 - a11k1carre
    a = k2.integer_representation()
    ab = v.integer_representation()
    print("(K1,K2) = ", (a,ab))
    
    P = 0xb73cf44702000000 #taps in LFSR
    GF2.<x> = GF(2)[]
    K = GF(2^64);

    C = Integer(0x0000006e6f6e6101) # entry of LFSR
    K1= v # key1
    K2= k2 # key2

    C_bf = K._cache.fetch_int(C)
    k2_bf = K2
    k1_bf = K1

    R_bf = C_bf * k1_bf
    R_bf = R_bf * k1_bf
    R_bf = R_bf + k2_bf
    R_bf = R_bf * k1_bf
    R4 = R_bf.integer_representation()

   
    print("crypt(anon000 + 01, K1,k2) = ",hex(R4))
    
    C = Integer(0x6f6d796e6f6e6101) # entry of LFSR
    K1= v # key1
    K2= k2 # key2

    C_bf = K._cache.fetch_int(C)
    k2_bf = K2
    k1_bf = K1

    R_bf = C_bf * k1_bf
    R1 = R_bf.integer_representation()
    R_bf = R_bf * k1_bf
    R2 = R_bf.integer_representation()

    R_bf = R_bf + k2_bf
    R3 = R_bf.integer_representation()

    R_bf = R_bf * k1_bf
    R4 = R_bf.integer_representation()

   
    print("crypt(anonymo + 01, K1,k2) = ",hex(R4))
    
    C =  Integer(0x757365723d616e6f) # entry of LFSR
    C2 = Integer(0x0000000000000000) # entry of LFSR
    K1= v # key1
    K2= k2 # key2

    C_bf = K._cache.fetch_int(C)
    C2_bf = K._cache.fetch_int(C2)
    k2_bf = K2
    k1_bf = K1

    R_bf = C_bf * k1_bf # lfsr(c, k1)
    R_bf = R_bf + C2_bf # xor(C1, p2)
    R_bf = R_bf * k1_bf # lfsr(c2, k1)
    R_bf = R_bf + k2_bf # xor(c3, k2)
    R_bf = R_bf * k1_bf # lfsr( c4 , k1)
    
    #first R
    
    C = Integer(0x6e267065726d733d) # entry of LFSR
    C_bf = K._cache.fetch_int(C)
    C2_bf = R_bf
    
    R_bf = C_bf * k1_bf # lfsr(c, k1)
    R_bf = R_bf + C2_bf # xor(C1, p2)
    R_bf = R_bf * k1_bf # lfsr(c2, k1)
    R_bf = R_bf + k2_bf # xor(c3, k2)
    R_bf = R_bf * k1_bf # lfsr( c4 , k1)
    
    C = Integer(0x32) # entry of LFSR
    C_bf = K._cache.fetch_int(C)
    C2_bf = R_bf
    
    R_bf = C_bf * k1_bf # lfsr(c, k1)
    R_bf = R_bf + C2_bf # xor(C1, p2)
    R_bf = R_bf * k1_bf # lfsr(c2, k1)
    R_bf = R_bf + k2_bf # xor(c3, k2)
    R_bf = R_bf * k1_bf # lfsr( c4 , k1)
    
    R4 = R_bf.integer_representation()
    print(hex(R4))
    #R4 = int(input("r4>"),16)
    cert= f"user=anon&perms=2&sig={R4}".encode()
    print(f"CERT {base64.b64encode(cert).decode()}")
    
    ################################################
    
    C =  Integer(0x6f6e613d72657375) # entry of LFSR
    C2 = Integer(0x0000000000000000) # entry of LFSR
    K1= v # key1
    K2= k2 # key2

    C_bf = K._cache.fetch_int(C)
    C2_bf = K._cache.fetch_int(C2)
    k2_bf = K2
    k1_bf = K1

    R_bf = C_bf * k1_bf # lfsr(c, k1)
    R_bf = R_bf + C2_bf # xor(C1, p2)
    R_bf = R_bf * k1_bf # lfsr(c2, k1)
    R_bf = R_bf + k2_bf # xor(c3, k2)
    R_bf = R_bf * k1_bf # lfsr( c4 , k1)
    
    #first R
    
    C = Integer(0x3d736d726570266e) # entry of LFSR
    
    C_bf = K._cache.fetch_int(C)
    C2_bf = R_bf
    
    R_bf = C_bf * k1_bf # lfsr(c, k1)
    R_bf = R_bf + C2_bf # xor(C1, p2)
    R_bf = R_bf * k1_bf # lfsr(c2, k1)
    R_bf = R_bf + k2_bf # xor(c3, k2)
    R_bf = R_bf * k1_bf # lfsr( c4 , k1)
    
    C = Integer(0x32) # entry of LFSR
    C_bf = K._cache.fetch_int(C)
    C2_bf = R_bf
    
    R_bf = C_bf * k1_bf # lfsr(c, k1)
    R_bf = R_bf + C2_bf # xor(C1, p2)
    R_bf = R_bf * k1_bf # lfsr(c2, k1)
    R_bf = R_bf + k2_bf # xor(c3, k2)
    R_bf = R_bf * k1_bf # lfsr( c4 , k1)
    
    R4 = R_bf.integer_representation()
    print(hex(R4))
    #R4 = int(input("r4>"),16)
    cert= f"user=anon&perms=2&sig={R4}".encode()
    print(f"CERT {base64.b64encode(cert).decode()}")
     
    
    