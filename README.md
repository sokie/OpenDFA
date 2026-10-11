An opensource re-implementation of DFA.dll
Compatible with DFA.dll version 2.1.0.3

DFA has 2 "apis":
`u` license handshake (op1, when in[0]==1). Keys: two-key 3DES-EDE2.
Calls VM crypto method at index 36 which I just named VP36 (K1=E62A98BF52B6F237, K2=CE4CF7048C078080).  
  
request   in[0x04:0x14] = request GUID  
          in[0x30:0x38] = IV field          (== g(rec8), also the e head IV)  
          in[0x38:0x48] = nonceB (16B)  
          in[0x48:0xA8] = license = VP36-CBC( [H_A][const core], IV=in[0x30:0x38] )  
          H_A           = VP36-CBC-decrypt( in[0x38:0x48], IV=in[0x30:0x38] )   // first 16B  
  
response  out[0x00:0x10] = header  01000000 01000000 48000000 00000000  
          out[0x10:0x20] = echo in[0x38:0x48]                     (nonceB verbatim)  
          out[0x20:0x58] = VP36-CBC( [H_A(16) || STATEMENT(40)], IV = in[0x40:0x48] )  
            
seed      24B session seed (no clue yet how the real DFA generats it, we generate it from H_A game and seems to accept it)  
  
`e` per file call. g(x) = 3DES-EDE2-decrypt under baked K1=32A42F34024F628A, K2=9DBF3EFD0E2619A4.  
  
keys      K0 = g(seed[0:8]),  K1 = g(seed[8:16]),  IV = g(seed[16:24]) = g(rec8)  
          (seed = 16B at the live arena page +0x840, rec8 = 8B at +0x860, g(rec8) == u's IV field)    
  
head      C0 = out[0:8], C1 = out[8:16]  
          P0 = D_K0(E_K1(D_K0(C0))) XOR IV  = (X, seq)  
          P1 = D_K0(E_K1(D_K0(C1))) XOR C0  = (Y, 0)  
          i.e. out[0:16] = 3DES-EDE2-CBC( descriptor {X, seq, Y, 0}, K0/K1, IV )  
  
descr     X = saw just 2 values, either `0x40A` for direct file calls, `1` for path/directories requests  
          seq = the call's seq,  Y = 0 then 1 across records  
            
payload   in[0x10:len] is VM-pre-filled/plain, `e` only writes the 16B head and clears state bit 0x400  
  
