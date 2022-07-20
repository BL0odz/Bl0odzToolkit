
## rewrite from : https://github.com/bennof/mdbrecovery/blob/master/src/mdb.c

import os
import struct

JET3_XOR = [0x86,0xfb,0xec,0x37,0x5d,0x44,0x9c,0xfa,0xc6,
            0x5e,0x28,0xe6,0x13,0xb6,0x8a,0x60,0x54,0x94]

JET4_XOR = [0x6aba,0x37ec,0xd561,0xfa9c,0xcffa,
            0xe628,0x272f,0x608a,0x0568,0x367b,
            0xe3c9,0xb1df,0x654b,0x4313,0x3ef3,
            0x33b1,0xf008,0x5b79,0x24ae,0x2a7c]

MDB_VER_JET3 = 0
MDB_VER_JET4 = 1
MDB_VER_ACCDB2007 = 0x02
MDB_VER_ACCDB2010 = 0x0103

def recover(mdbpath):
    buff = open(mdbpath, 'rb').read(0x400)
    version = struct.unpack('<I', buff[0x14 : 0x14+4])[0]
    if version == MDB_VER_JET3:
        print("DB Version: JET 3\n")
    elif version == MDB_VER_JET4:
        print("DB Version: JET 4\n")
    elif version == MDB_VER_JET3:
        print("DB Version: AccessDB 2007\n")
    elif version == MDB_VER_JET3:
        print("DB Version: AccessDB 2010\n")
    else:
        print("ERROR unkown version: %x\n" % version)

    passwd = []
    if version == 0:
        passwd = list(buff[0x42 : 0x42+20])
        for i in range(18):
            passwd[i] ^= JET3_XOR[i]
        print("Password : " + ''.join([chr(c) for c in passwd]))
    elif version == 1:
        temp = buff[0x42 : 0x42+40]
        passwd = []
        for i in range(int(len(temp)/2)):
            passwd.append(struct.unpack('<H', temp[2*i:2*i+2])[0])
        magic = struct.unpack('<H', buff[0x66:0x66+2])[0] ^ JET4_XOR[18]
        for i in range(20):
            passwd[i] ^= JET4_XOR[i]
            if passwd[i] > 255:
                passwd[i] ^= magic
        print("Password List : " + str(passwd))
        print("Password : " + ''.join([chr(c) for c in passwd]))
            
if __name__ == '__main__':
    if len(os.sys.argv) < 2:
        print("\nusage : python MDBPassRecovery.py <mdb file path>")
    else:
        recover(os.sys.argv[1])
