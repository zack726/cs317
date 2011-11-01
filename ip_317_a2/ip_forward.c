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
    
    printf("Packet Loss: %f, Forwarded: %f, Dropped: %f", dropped/forwarded, forwarded, dropped);
    
    FTEntry* curr = ft->head;
    for(int i=0; i<ft->numentries; i++){
        curr = curr->next;
        printf("%i.%i.%i.%i/%i %i\n", curr->ip->first8, curr->ip->second8, curr->ip->third8, curr->ip->fourth8, curr->ip->prefix_len, curr->nic->nic);
        fflush(stdout);
    }
    return 0;
}

void readIpv4(const char* fname, ForwardingTable* ft, NICTable* nt){
    errno=0;
    FILE* fileptr = fopen(fname, "r");
    if(errno!=0){
        perror("Unable to open file");
        exit(1);
    }
    char* linbuf = (char*)malloc(sizeof(char)*STDSTRBUFSIZ);
//    char* dbuf = (char*)malloc(sizeof(char)*STDSTRBUFSIZ);
    IPAddress* tmpip = (IPAddress*)malloc(sizeof(IPAddress));
//    uint32_t dbufi=0;
    uint32_t nic_or_id = -1;
    char line_type;
//    uint32_t tmpint;
    ParsedDataType pdt = LINETYPE;
    bool isFirstLine = true;
//    bool isInitOrUpdate = true;
    
    while(fgets(linbuf, STDSTRBUFSIZ, fileptr) != NULL ){
        pdt=LINETYPE;
        printf("%s", linbuf);
        if(isFirstLine){
            initializeNIC(nt, atoi(linbuf));
            isFirstLine = false;
        }
        else{
            char ignore;
            if(linbuf[0] == 'T'){
                line_type = TABLEINSERT;
                sscanf(linbuf, "%c %d.%d.%d.%d/%d %d", &ignore, (int*)&tmpip->first8, (int*)&tmpip->second8, (int*)&tmpip->third8, (int*)&tmpip->fourth8, (int*)&tmpip->prefix_len, &nic_or_id);
            }
            else if(linbuf[0] == 'P'){
                line_type = PACKET;
                sscanf(linbuf, "%c %d.%d.%d.%d %d", &ignore, (int*)&tmpip->first8, (int*)&tmpip->second8, (int*)&tmpip->third8, (int*)&tmpip->fourth8, &nic_or_id);
            }
            else if(linbuf[0] == 'U'){
                line_type = TABLEUPDATE;
                
            }
            print_ip_prefix(tmpip);
            printf("\n");
//            free(dbuf);
//            dbuf = (char*)malloc(sizeof(char)*STDSTRBUFSIZ);
//            dbufi=0;
//            for(uint32_t i=0; i < STDSTRBUFSIZ; i++){
//                if(linbuf[i]==' ' || linbuf[i]=='.' || linbuf[i]=='\n' || linbuf[i]=='/' || (linbuf[i]=='\r' && linbuf[i+1]=='\n')){
//                    tmpint = strtoul(dbuf, NULL, 0);
//                    if(pdt == LINETYPE){
//                        pdt++;
//                        line_type = dbuf[0];
//                        if(dbuf[0] == TABLEINSERT || dbuf[0] == TABLEUPDATE){
//                            isInitOrUpdate = true;
//                        }
//                        else if(dbuf[0] == PACKET){
//                            isInitOrUpdate = false;
//                        }
//                        else{
//                            perror("Unknown value of dbuf[0]");
//                        }
//                    }
//                    else if(pdt == FIRSTIPPART){
//                        pdt++;
//                        tmpip->first8 = (uint8_t)tmpint;
//                    }
//                    else if(pdt == SECONDIPPART){
//                        pdt++;
//                        tmpip->second8 = (uint8_t)tmpint;
//                    }
//                    else if(pdt == THIRDIPPART){
//                        pdt++;
//                        tmpip->third8 = (uint8_t)tmpint;
//                    }
//                    else if(pdt == FOURTHIPPART){
//                        pdt++;
//                        tmpip->fourth8 = (uint8_t)tmpint;
//                    }
//                    else if(pdt == PREFIXLEN){
//                        if(isInitOrUpdate){ //if is init or update, read prefixlen. 
//                            pdt++;
//                            tmpip->prefix_len = (uint8_t)tmpint;
//                        }
//                        else{ //else read packet id
//                            nic_or_id = tmpint;
//                            break;
//                        }
//                    }
//                    else if(pdt == NICORID){
//                        nic_or_id = tmpint;
//                        pdt=LINETYPE; //wrap back around, next line
//                        break;
//                    }
//                    else{
//                        perror("Line parsing error: unknown ParsedDataType/pdt");
//                    }
//                    free(dbuf);
//                    dbuf = (char*)malloc(sizeof(char)*STDSTRBUFSIZ);
//                    dbufi=0;
//                }
//                else{
//                    dbuf[dbufi++] = linbuf[i];
//                }
//            }
            if(line_type == TABLEINSERT){
                insertIntoFT(ft, nt, tmpip, nic_or_id);
            }
            else if(line_type == TABLEUPDATE){
                
            }
            else if(line_type == PACKET){
                routePacket(ft, nt, tmpip, nic_or_id);
            }
            else{
                perror("Unknown line type");
            }                
        }
        fflush(stdout);
        nic_or_id = -1;
        tmpip = (IPAddress*)malloc(sizeof(IPAddress));
    }
    fclose(fileptr);
//    free(linbuf);
//    free(dbuf);
}

void insertIntoFT(ForwardingTable* ft, NICTable* nt, IPAddress* ip, uint32_t nic){
    FTEntry* fte = (FTEntry*)malloc(sizeof(FTEntry));
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
    ForwardingTable* ft = (ForwardingTable*)malloc(sizeof(ForwardingTable));
    ft->head = (FTEntry*)malloc(sizeof(FTEntry)); //dummy header node
    ft->tail = ft->head;
    ft->numentries=0;  
    return ft;
}

NICTable* constructNT(void){
    NICTable* nt = (NICTable*)malloc(sizeof(NICTable));
    nt->head = (NICEntry*)malloc(sizeof(NICEntry)); //dummy header node
    nt->tail = nt->head;
    nt->numentries=0;  
    return nt;
}

void initializeNIC(NICTable* nt, uint32_t numentries){
    for(int32_t i=0; i<numentries; i++){
        NICEntry* ne = (NICEntry*)malloc(sizeof(NICEntry));
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
        if(ipcmp_host(ip, curr->ip) == 0){                                      //if this forwarding table entry matches the given ip
            if(curr->next != NULL && ipcmp_host(ip, curr->next->ip) == 0){      //check the next one. if it exists, and also matches, 
                                                                                //then it will be a better match (192.168.0.0/16 comes before 192.168.0.0/24)
                continue;                                                       //so we continue
            }               
            else{                                                               //otherwise this IS the longest prefix match, use it.
                found_fte = curr;
                break;
            }
        }
    }
    return found_fte;
}

void routePacket(ForwardingTable* ft, NICTable* nt, IPAddress* ip, uint32_t packetid){  
    printf("PACKETID: %i packet loss %f\n", packetid, (dropped/(forwarded+dropped)));
    fflush(stdout);
    FTEntry* fte = findEntryByIp(ft, ip);
    if(fte == NULL){
        printf("O %i.%i.%i.%i -1\n", ip->first8, ip->second8, ip->third8, ip->fourth8);
        dropped++;
    }
    else{
        NICEntry* nice = fte->nic;
        printf("O %i.%i.%i.%i %i\n", ip->first8, ip->second8, ip->third8, ip->fourth8, nice->nic);   
        forwarded++;
    }
}


/*
 *  Same as strcmp, but for ips, in that
 *
 *   A zero value indicates that both ips are equal.
 *   A value greater than zero indicates that the first byte that does not match has a greater value in str1 than in str2; And a value less than zero indicates the opposite.
 *
 */
int ipcmp_prefix(IPAddress* ipOne, IPAddress* ipTwo){
    if(ipOne->first8 > ipTwo->first8){
        return 1;
    }
    else if(ipOne->first8 < ipTwo->first8){
        return -1;
    }
    if(ipOne->second8 > ipTwo->second8){
        return 1;
    }
    else if(ipOne->second8 < ipTwo->second8){
        return -1;
    }
    if(ipOne->third8 > ipTwo->third8){
        return 1;
    }
    else if(ipOne->third8 < ipTwo->third8){
        return 0;
    }
    if(ipOne->fourth8 > ipTwo->fourth8){
        return 1;
    }
    else if(ipOne->fourth8 < ipTwo->fourth8){
        return 0;
    }
    
    if(ipOne->prefix_len > ipTwo->prefix_len){
        return 1;
    }
    else if(ipOne->prefix_len < ipTwo->prefix_len){
        return -1;
    }
    else{
        return 0;
    }
}
/*
 * Similar to ipcmp_prefix, but takes a host ip and masks it to match the
 * forwarding table entry for comparison
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
    IPAddress* tmphost = uinttoip(iptoformat);
    tmphost->prefix_len = prefix_len;
//    printf("IP: "); print_ip_host(host); printf("was converted to: "); print_ip_prefix(tmphost); printf("and is being compared to: "); print_ip_prefix(ip_from_fte); printf("\n");
    return ipcmp_prefix(tmphost, ip_from_fte);
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
    IPAddress* ip = (IPAddress*)malloc(sizeof(IPAddress));
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
