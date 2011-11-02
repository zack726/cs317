//
//  ip_forward.c
//  ip_317_a2
//
//  Created by Zachary Siddall on 10/29/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include "ip_forward.h"
double forwarded;
double dropped;

int main(int argc, const char* argv[]){
    switch(argc){
        case 2:
            break;
        default:
            printf("Incorrect usage. Correct usage =is: ipv4_router <filename>");
    }    
    forwarded = 0;
    dropped = 0;
    
    ForwardingTable* ft = constructFT();
    NICTable* nt = constructNT();
    readIpv4(argv[1], ft, nt);
    printf("\n");    
    FTEntry* curr = ft->head;
    for(int i=0; i<ft->numentries; i++){
        curr = curr->next;
        printf("%i.%i.%i.%i/%i %i\n", curr->ip->first8, curr->ip->second8, curr->ip->third8, curr->ip->fourth8, curr->ip->prefix_len, curr->nic->nic);
        fflush(stdout);
    }
    
    printf("Packet Loss: %f, Forwarded: %f, Dropped: %f", dropped/forwarded, forwarded, dropped);

    return 0;
}

void readIpv4(const char* fname, ForwardingTable* ft, NICTable* nt){
    errno=0;
    FILE* fileptr = fopen(fname, "r");
    if(errno!=0){
        perror("Unable to open file");
        exit(1);
    }
    char* linbuf = (char*)malloc(sizeof(char)*STDSTRBUFSIZ); //MEMUSG: this line buffer is reused by every loop iteration and freed at then end of this function
    IPAddress* tmpip = (IPAddress*)malloc(sizeof(IPAddress)); //MEMUSG: need space for ip allocated for each iteration of this while loop
    uint32_t nic_or_id = -1;
    bool isFirstLine = true;
    
    while(fgets(linbuf, STDSTRBUFSIZ, fileptr) != NULL ){
        if(isFirstLine){
            initializeNIC(nt, atoi(linbuf));
            isFirstLine = false;
        }
        else{
            char ignore;
            if(linbuf[0] == 'T'){
                sscanf(linbuf, "%c %d.%d.%d.%d/%d %d", &ignore, (int*)&tmpip->first8, (int*)&tmpip->second8, (int*)&tmpip->third8, (int*)&tmpip->fourth8, (int*)&tmpip->prefix_len, &nic_or_id);
                insertIntoFT(ft, nt, tmpip, nic_or_id);
            }
            else if(linbuf[0] == 'P'){
                sscanf(linbuf, "%c %d.%d.%d.%d %d", &ignore, (int*)&tmpip->first8, (int*)&tmpip->second8, (int*)&tmpip->third8, (int*)&tmpip->fourth8, &nic_or_id);
                routePacket(ft, nt, tmpip, nic_or_id);
                //after packet is routed, we have no need of it's tmpip memory anymore
                free(tmpip);
            }
            else if(linbuf[0] == 'U'){

            }
        }
        nic_or_id = -1;
        tmpip = (IPAddress*)malloc(sizeof(IPAddress)); //MEMUSG: since tmpip will either have been freed (in the case of a packet) or needs to be used (if ft entry), we alloc again.
    }
    fclose(fileptr);
    free(linbuf);
}

void insertIntoFT(ForwardingTable* ft, NICTable* nt, IPAddress* ip, uint32_t nic){    
    FTEntry* fte = (FTEntry*)malloc(sizeof(FTEntry)); //MEMUSG: need space for each new fte into table - each call to this function
    fte->ip = ip;
    NICEntry* curr_ne = nt->head;
    for(int i=0; i<nt->numentries; i++){
        curr_ne = curr_ne->next;
        if(curr_ne->nic == nic){
            break;
        }
    }
    //(soft) assert curr_ne is the nic we are looking for
    fte->nic = curr_ne;
    //ignore metric for now
    FTEntry* curr = ft->head;
    while(curr->next != NULL){
        curr = curr->next;
        if(ipcmp_prefix(ip, curr->ip) < 0){ //if this entry is greater than the ip we are inserting
            FTEntry* old_prev = curr->prev;
            old_prev->next = fte;
            curr->prev = fte;
            fte->prev = old_prev;
            fte->next = curr;
            curr = fte; //ensure the if curr->next==null condition 4 lines below not met
            break;
        }
    }
    if(curr->next == NULL){ //insert at end of list
        FTEntry* old_prev = curr;
        old_prev->next = fte;
        fte->prev = old_prev;
        fte->next = NULL;
    }
    ft->numentries++;
}

ForwardingTable* constructFT(void){
    ForwardingTable* ft = (ForwardingTable*)malloc(sizeof(ForwardingTable)); //MEMUSG: space for forwarding table metadata
    ft->head = (FTEntry*)malloc(sizeof(FTEntry)); //MEMUSG: dummy header node
    ft->tail = ft->head;
    ft->numentries=0;  
    return ft;
}

NICTable* constructNT(void){
    NICTable* nt = (NICTable*)malloc(sizeof(NICTable)); //MEMUSG: space for NIC table metadata
    nt->head = (NICEntry*)malloc(sizeof(NICEntry)); //MEMUSG: dummy header node
    nt->tail = nt->head;
    nt->numentries=0;  
    return nt;
}

void initializeNIC(NICTable* nt, uint32_t numentries){
    for(int32_t i=0; i<numentries; i++){
        NICEntry* ne = (NICEntry*)malloc(sizeof(NICEntry)); //MEMUSG: space for each entry in the NIC data structure
        ne->nic = i;
        NICEntry* tmptail = nt->tail;   //get ptr to current tail  
        tmptail->next = ne;             //set that node's next pointer to point to the newly inserted entry
        //(which will be new tail)
        ne->prev = tmptail;             //set ne/new tail's prev ptr to old tail/tmp tail
        nt->tail = ne;                  //update meta-tail info
        nt->numentries++;
    }
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         

FTEntry* findEntryByIp(ForwardingTable* ft, IPAddress* ip){
    FTEntry* found_fte = NULL;
    FTEntry* curr = ft->head;
    
    if(ft == NULL || curr == NULL){
        return NULL;
    }   
    while(curr->next!=NULL){    //if next is null on first itr, will just go right to end. which is of course fine, 
        //because the first node in ft is a dummy. Also note, if it breaks without found_fte
        //being set - then we didnt find find_fte
        curr = curr->next;
        int8_t ipcmp = ipcmp_host(ip, curr->ip);
        if(ipcmp == 0){                                      //if this forwarding table entry matches the given ip
            if(curr->next != NULL && ipcmp_host(ip, curr->next->ip) == 0){      //check the next one. if it exists, and also matches, 
                                                                                //then it will be a better match (ex. 192.168.0.0/16 comes before 192.168.0.0/24)
                continue;                                                       //so we continue 
            }               
            else{                                                               //otherwise this IS the longest prefix match, use it.
                found_fte = curr;
                break;
            }
        }
        else if(ipcmp < 0){ //if we are past all possible matches, an ip can never have a prefix match that is greater than it (prefix is always less than the ip)
            break;
        }
    }
    return found_fte;
}

void routePacket(ForwardingTable* ft, NICTable* nt, IPAddress* ip, uint32_t packetid){  
//    printf("PACKETID: %i packet loss %f\n", packetid, (dropped/(forwarded+dropped)));
//    fflush(stdout);
    FTEntry* fte = findEntryByIp(ft, ip);
    if(fte == NULL){
        printf("O %i -1\n", packetid);
        dropped++;
    }
    else{
        printf("O %i %i\n", packetid, fte->nic->nic);   
        forwarded++;
    }
}


/*
 *  Same as strcmp, but for ips, in that
 *
 *   A zero value indicates that both ips are equal.
 *   A value greater than zero indicates that ipOne is greater than ipTwo; And a value less than zero indicates the opposite.
 *
 */
int ipcmp_prefix(IPAddress* ipOne, IPAddress* ipTwo){
    uint32_t ipOneAsUint = iptouint(ipOne);
    uint32_t ipTwoAsUint = iptouint(ipTwo);
    if(ipOneAsUint == ipTwoAsUint){
        return 0;
    }
    else if(ipOneAsUint > ipTwoAsUint){
        return 1;
    }
    else{
        return -1;
    }
}
/*
 * Wrapper for ipcmp_prefix, masks out bits not used by prefix 
 * (aka if prefix length = k, masks out 32-k rightmost bits) then calls
 * ipcmp_prefix
 *
 */
int ipcmp_host(IPAddress* host, IPAddress* ip_from_fte){ //host vs forward table entry
    uint8_t prefix_len = ip_from_fte->prefix_len;
    uint32_t mask=0;
    for(int i=0; i<prefix_len; i++){
        mask+=pow(2, i);
    }
    mask = (mask<<(32-prefix_len));    
    uint32_t iptoformat = iptouint(host);
    iptoformat = iptoformat&mask;
    IPAddress* _tmphost = uinttoip(iptoformat);
    _tmphost->prefix_len = prefix_len;
    uint32_t ipcmp_prefix_result = ipcmp_prefix(_tmphost, ip_from_fte);
    free(_tmphost); //MEMUSG FREEME1 freed
    return ipcmp_prefix_result;
}

uint32_t iptouint(IPAddress* ip){
    uint32_t ipasuint = 0;
    ipasuint += (ip->first8)<<24;
    ipasuint += (ip->second8)<<16;
    ipasuint += (ip->third8)<<8;
    ipasuint += (ip->fourth8);
    return ipasuint;
}
IPAddress* uinttoip(uint32_t uint){
    IPAddress* ip = (IPAddress*)malloc(sizeof(IPAddress)); //MEMUSG: FREEME1 as these are generally temporary objects, they should be tracked and probably deleted
    uint32_t uint_cpy = uint;
    ip->first8 = (uint8_t)(uint_cpy>>24);
    uint_cpy = uint;
    ip->second8 = (uint8_t)(uint_cpy>>16);
    uint_cpy = uint;
    ip->third8 = (uint8_t)(uint_cpy>>8);
    uint_cpy = uint;
    ip->fourth8 = (uint8_t)(uint_cpy);
    return ip;
}
void print_ip_host(IPAddress* ip){
    printf(" %i.%i.%i.%i ", ip->first8, ip->second8, ip->third8, ip->fourth8);

}
void print_ip_prefix(IPAddress* ip){
    printf(" %i.%i.%i.%i/%i ", ip->first8, ip->second8, ip->third8, ip->fourth8, ip->prefix_len);
}
