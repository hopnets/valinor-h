#ifndef VALINOR_H
#define VALINOR_H

struct vhdr {
    __be32  id;
    __be64  t[2];
    __be16  datalen;
} __attribute__((packed));


static __inline __be64
htonll(const __u64 input)
{
    __u64 rval;
    __u8 *data = (__u8 *)&rval;

    data[0] = input >> 56;
    data[1] = input >> 48;
    data[2] = input >> 40;
    data[3] = input >> 32;
    data[4] = input >> 24;
    data[5] = input >> 16;
    data[6] = input >> 8;
    data[7] = input >> 0;

    return rval;
}


#endif  // VALINOR_H