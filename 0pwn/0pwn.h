//
//  0pwn.h
//  0pwn
//
//  Created by Zachary Keffaber on 7/11/22.
//

#ifndef _pwn_h
#define _pwn_h

#include <stdio.h>
#include <Foundation/Foundation.h>
int openpwnage64(void);
bool rootify(pid_t pid, mach_port_t tfp0, uint64_t ourproc);
void unsandbox(pid_t pid, mach_port_t tfp0, uint64_t ourproc);
//bool setcsflags(pid_t pid, mach_port_t tfp0, uint64_t ourproc);
//void platformize(pid_t pid, mach_port_t tfp0, uint64_t ourproc);
#endif /* _pwn_h */
