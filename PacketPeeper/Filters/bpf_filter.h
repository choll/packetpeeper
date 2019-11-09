
#ifndef PPPBPF_FILTER_H_
#define PPPBPF_FILTER_H_

/* renamed because it seems that libpcap defines a bpf_filter symbol */

struct bpf_insn;

u_int bpf_filter2(register const struct bpf_insn *pc, register u_char *p, u_int wirelen, register u_int buflen);

#endif
