/*
 *
 *  This is free software. You can redistribute it and/or modify under
 *  the terms of the GNU General Public License version 2.
 *
 *   Copyright (C) 2004 by Guillermo Grandes
 *
 */
#include "hunt.h"
#include <sys/uio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

// tap.c
extern unsigned char my_eth_mac[ETH_ALEN];
extern unsigned int my_eth_ip;

char eth_brd[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
char eth_null[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned int ip_any = 0;

//
int linksock = -1;
//
int verbose = 0;
int quiet = 0;
char *eth_device = NULL;
int count = 1;
int wait_time = 0;
int opcode = 1;
char *eth_src_mac = NULL;
char *eth_dst_mac = NULL;
char *arp_src_mac = NULL;
char *arp_src_ip  = NULL;
char *arp_dst_mac = NULL;
char *arp_dst_ip  = NULL;
//

void usage()
{
  fprintf(stderr, "ARP-Sender 1.0, based on Hunt 1.5\n\n"
    "Usage:\n"
    "  -q             : quiet\n"
    "  -v             : verbose\n"
    "  -c count       : how many packets to send\n"
    "  -w seconds     : how many seconds wait after sends\n"
    "  -I device      : which ethernet device to use (eth0)\n"
    "  -F eth-src-mac : ethernet source mac address\n"
    "  -T eth-dst-mac : ehternet destination mac address\n"
    "  -o opcode      : arp opcode\n"
    "  -S arp-src-mac : arp sender mac address\n"
    "  -s arp-src-ip  : arp sender ip address\n"
    "  -D arp-dst-mac : arp target mac address\n"
    "  -d arp-dst-ip  : arp target ip address\n"
    "\n"
    "opcode strings: (ebtables -h arp)\n"
    "1 = Request\n"
    "2 = Reply\n"
    "\n");
  exit(2);
}

int main(int argc, char *argv[])
{
  int ch;
  while ((ch = getopt(argc, argv, "h?qvc:w:I:F:T:o:S:D:s:d:")) != EOF) {
    switch(ch) {
    case 'q':
      quiet=1;
      verbose=0;
      break;
    case 'v':
      verbose=1;
      quiet=0;
      break;
    case 'c':
      count = atoi(optarg);
      if ((count < 1) || (count > 1024)) count = 1; // Anti-DoS
      break;
    case 'w':
      wait_time = atoi(optarg);
      if ((wait_time < 1) || (wait_time > 1024)) wait_time = 0;
      break;
    case 'I':
      eth_device = optarg;
      break;
    case 'F': {
      char *buf = (char *)ether_aton(optarg);
      if (!buf) {
        fprintf(stderr, "invalid mac-addr in option -%c\n", ch);
        usage();
      }
      eth_src_mac = (char *)malloc(ETH_ALEN);
      memcpy(eth_src_mac, buf, ETH_ALEN);
      //memcpy(eth_src_mac, (char *)ether_aton(optarg), ETH_ALEN);
      break;
    }
    case 'T': {
      char *buf = (char *)ether_aton(optarg);
      if (!buf) {
        fprintf(stderr, "invalid mac-addr in option -%c\n", ch);
        usage();
      }
      eth_dst_mac = (char *)malloc(ETH_ALEN);
      memcpy(eth_dst_mac, buf, ETH_ALEN);
      //memcpy(eth_dst_mac, (char *)ether_aton(optarg), ETH_ALEN);
      break;
    }
    case 'o':
      opcode = atoi(optarg);
      break;
    case 'S': {
      char *buf = (char *)ether_aton(optarg);
      if (!buf) {
        fprintf(stderr, "invalid mac-addr in option -%c\n", ch);
        usage();
      }
      arp_src_mac = (char *)malloc(ETH_ALEN);
      memcpy(arp_src_mac, (char *)ether_aton(optarg), ETH_ALEN);
      break;
    }
    case 's':
      arp_src_ip = optarg;
      break;
    case 'D': {
      char *buf = (char *)ether_aton(optarg);
      if (!buf) {
        fprintf(stderr, "invalid mac-addr in option -%c\n", ch);
        usage();
      }
      arp_dst_mac = (char *)malloc(ETH_ALEN);
      memcpy(arp_dst_mac, (char *)ether_aton(optarg), ETH_ALEN);
      break;
    }
    case 'd':
      arp_dst_ip = (char *)optarg;
      break;
    case 'h':
    case '?':
    default:
      usage();
    }
  }
  argc -= optind;
  argv += optind;

  if (!eth_device)
    usage();

  linksock = tap(eth_device, 1);

  if (!eth_src_mac) {
    eth_src_mac = (char *)malloc(ETH_ALEN);
    memcpy(eth_src_mac, my_eth_mac, ETH_ALEN);
  }
  if (!eth_dst_mac) {
    eth_dst_mac = (char *)malloc(ETH_ALEN);
    memcpy(eth_dst_mac, eth_brd, ETH_ALEN);
  }
  if (!arp_src_mac) {
    arp_src_mac = (char *)malloc(ETH_ALEN);
    memcpy(arp_src_mac, my_eth_mac, ETH_ALEN);
  }
  if (!arp_src_ip) {
    char *tmp = (char *)inet_ntoa(my_eth_ip);
    arp_src_ip = (char *)malloc(strlen(tmp));
    strcpy(arp_src_ip, tmp);
  }
  if (!arp_dst_mac) {
    arp_dst_mac = (char *)malloc(ETH_ALEN);
    memcpy(arp_dst_mac, eth_null, ETH_ALEN);
  }
  if (!arp_dst_ip) {
    char *tmp = (char *)inet_ntoa(ip_any);
    arp_dst_ip = (char *)malloc(strlen(tmp));
    strcpy(arp_dst_ip, tmp);
  }
 
  if (!opcode)   //if (argc != 1)
    usage();

  struct arp_spec as;
  int i;
  
  as.src_mac = eth_src_mac;
  as.dst_mac = eth_dst_mac;
  as.oper = htons(opcode); // ARPOP_REPLY / ARPOP_REQUEST
  as.sender_mac = arp_src_mac;
  as.sender_addr = inet_addr(arp_src_ip);
  as.target_mac = arp_dst_mac;
  as.target_addr = inet_addr(arp_dst_ip);
  
  for (i = 1; i <= count; i++) {
    if (wait_time && i > 1) sleep(wait_time);
    if (!quiet || verbose) {
      printf("sending dev=%s", eth_device);
      printf(" eth_src_mac=");
      print_eth_mac(as.src_mac);
      printf(" eth_dst_mac=");
      print_eth_mac(as.dst_mac);
      printf(" opcode=%d", htons(as.oper));
      printf(" arp_src_mac=");
      print_eth_mac(as.sender_mac);
      printf(" arp_src_ip=%s", inet_ntoa(as.sender_addr));
      printf(" arp_dst_mac=");
      print_eth_mac(as.target_mac);
      printf(" arp_dst_ip=%s", inet_ntoa(as.target_addr));
      printf("\n");
    }
    send_arp_packet(&as);
    fflush(stdout);
    fflush(stderr);
  }
  
  close(linksock);
}
