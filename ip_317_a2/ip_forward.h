//
//  ip_forward.h
//  ip_317_a2
//
//  Created by Zachary Siddall on 10/29/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef ip_317_a2_ip_forward_h
#define ip_317_a2_ip_forward_h

#include <errno.h> //errno
#include <stdio.h> //FILE, fopen
#include <sys/mman.h>
#include <stdint.h> //int32_t...
#include <stdbool.h> //bool
#include <stdlib.h> //atoi
#include <string.h> //memcpy
#include <math.h> //pow

#define UNREACHABLE_HOST 1000
#define STDSTRBUFSIZ 255
#define OVERFLOWSTRBUFSIZ 1024*255
#define IPADRLEN 32

typedef unsigned char byte;

typedef struct NICEntry{
    uint32_t nic;
    struct FTEntry* neighbour_table; //represented currently as a linked list
    struct NICEntry* next;
    struct NICEntry* prev;
}NICEntry;

typedef struct IPAddress{
    uint8_t first8, second8, third8, fourth8;
    uint8_t prefix_len;
}IPAddress;

typedef struct FTEntry{
    IPAddress* ip;
    uint32_t metric;
    NICEntry* nic;
    struct FTEntry* next;
    struct FTEntry* prev;
}FTEntry;

typedef struct ForwardingTable{
    FTEntry* head;
    FTEntry* tail;
    int32_t numentries;
}ForwardingTable;

typedef struct NICTable{
    NICEntry* head;
    NICEntry* tail;
    int8_t numentries;
}NICTable;

void readIpv4(const char* fname, ForwardingTable* ft, NICTable* nt);
void insertIntoFT(ForwardingTable* ft, NICTable* nt, 
                  IPAddress* ip, uint32_t nic);
void routePacket(ForwardingTable* ft, NICTable* nt, IPAddress* ip, uint32_t packetid);
ForwardingTable* constructFT(void);
int ipcmp_prefix(IPAddress* ipOne, IPAddress* ipTwo);
int ipcmp_host(IPAddress* host, IPAddress* ip_from_fte); //host vs forward table entry
NICTable* constructNT(void);
void initializeNIC(NICTable* nt, uint32_t numentries);
FTEntry* findEntryByIp(ForwardingTable* ft, IPAddress* ip);
uint32_t iptouint(IPAddress* ip);
IPAddress* uinttoip(uint32_t uint);
void print_ip_host(IPAddress* ip);
void print_ip_prefix(IPAddress* ip);

#endif
