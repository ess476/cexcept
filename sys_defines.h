#pragma once

#define accept(...)	 except_sys(accept(__VA_ARGS__))

#define accept4(...)	 except_sys(accept4(__VA_ARGS__))

#define access(...)	 except_sys(access(__VA_ARGS__))

#define acct(...)	 except_sys(acct(__VA_ARGS__))

#define add_key(...)	 except_sys(add_key(__VA_ARGS__))

#define adjtimex(...)	 except_sys(adjtimex(__VA_ARGS__))

#define afs_syscall(...)	 except_sys(afs_syscall(__VA_ARGS__))

#define alarm(...)	 except_sys(alarm(__VA_ARGS__))

#define alloc_hugepages(...)	 except_sys(alloc_hugepages(__VA_ARGS__))

#define arch_prctl(...)	 except_sys(arch_prctl(__VA_ARGS__))

#define arm_fadvise(...)	 except_sys(arm_fadvise(__VA_ARGS__))

#define arm_fadvise64_64(...)	 except_sys(arm_fadvise64_64(__VA_ARGS__))

#define arm_sync_file_range(...)	 except_sys(arm_sync_file_range(__VA_ARGS__))

#define bdflush(...)	 except_sys(bdflush(__VA_ARGS__))

#define bind(...)	 except_sys(bind(__VA_ARGS__))

#define bpf(...)	 except_sys(bpf(__VA_ARGS__))

#define break(...)	 except_sys(break(__VA_ARGS__))

#define brk(...)	 except_sys(brk(__VA_ARGS__))

#define cacheflush(...)	 except_sys(cacheflush(__VA_ARGS__))

#define capget(...)	 except_sys(capget(__VA_ARGS__))

#define capset(...)	 except_sys(capset(__VA_ARGS__))

#define chdir(...)	 except_sys(chdir(__VA_ARGS__))

#define chmod(...)	 except_sys(chmod(__VA_ARGS__))

#define chown(...)	 except_sys(chown(__VA_ARGS__))

#define chown32(...)	 except_sys(chown32(__VA_ARGS__))

#define chroot(...)	 except_sys(chroot(__VA_ARGS__))

#define clock_getres(...)	 except_sys(clock_getres(__VA_ARGS__))

#define clock_gettime(...)	 except_sys(clock_gettime(__VA_ARGS__))

#define clock_nanosleep(...)	 except_sys(clock_nanosleep(__VA_ARGS__))

#define clock_settime(...)	 except_sys(clock_settime(__VA_ARGS__))

#define __clone2(...)	 except_sys(__clone2(__VA_ARGS__))

#define clone2(...)	 except_sys(clone2(__VA_ARGS__))

#define clone(...)	 except_sys(clone(__VA_ARGS__))

#define close(...)	 except_sys(close(__VA_ARGS__))

#define connect(...)	 except_sys(connect(__VA_ARGS__))

#define copy_file_range(...)	 except_sys(copy_file_range(__VA_ARGS__))

#define creat(...)	 except_sys(creat(__VA_ARGS__))

#define create_module(...)	 except_sys(create_module(__VA_ARGS__))

#define delete_module(...)	 except_sys(delete_module(__VA_ARGS__))

#define dup2(...)	 except_sys(dup2(__VA_ARGS__))

#define dup(...)	 except_sys(dup(__VA_ARGS__))

#define dup3(...)	 except_sys(dup3(__VA_ARGS__))

#define epoll_create1(...)	 except_sys(epoll_create1(__VA_ARGS__))

#define epoll_create(...)	 except_sys(epoll_create(__VA_ARGS__))

#define epoll_ctl(...)	 except_sys(epoll_ctl(__VA_ARGS__))

#define epoll_pwait(...)	 except_sys(epoll_pwait(__VA_ARGS__))

#define epoll_wait(...)	 except_sys(epoll_wait(__VA_ARGS__))

#define eventfd2(...)	 except_sys(eventfd2(__VA_ARGS__))

#define eventfd(...)	 except_sys(eventfd(__VA_ARGS__))

#define execve(...)	 except_sys(execve(__VA_ARGS__))

#define execveat(...)	 except_sys(execveat(__VA_ARGS__))

#define _exit(...)	 except_sys(_exit(__VA_ARGS__))

#define exit(...)	 except_sys(exit(__VA_ARGS__))

#define _Exit(...)	 except_sys(_Exit(__VA_ARGS__))

#define exit_group(...)	 except_sys(exit_group(__VA_ARGS__))

#define faccessat(...)	 except_sys(faccessat(__VA_ARGS__))

#define fadvise64(...)	 except_sys(fadvise64(__VA_ARGS__))

#define fadvise64_64(...)	 except_sys(fadvise64_64(__VA_ARGS__))

#define fallocate(...)	 except_sys(fallocate(__VA_ARGS__))

#define fanotify_init(...)	 except_sys(fanotify_init(__VA_ARGS__))

#define fanotify_mark(...)	 except_sys(fanotify_mark(__VA_ARGS__))

#define fattach(...)	 except_sys(fattach(__VA_ARGS__))

#define fchdir(...)	 except_sys(fchdir(__VA_ARGS__))

#define fchmod(...)	 except_sys(fchmod(__VA_ARGS__))

#define fchmodat(...)	 except_sys(fchmodat(__VA_ARGS__))

#define fchown(...)	 except_sys(fchown(__VA_ARGS__))

#define fchown32(...)	 except_sys(fchown32(__VA_ARGS__))

#define fchownat(...)	 except_sys(fchownat(__VA_ARGS__))

#define fcntl(...)	 except_sys(fcntl(__VA_ARGS__))

#define fcntl64(...)	 except_sys(fcntl64(__VA_ARGS__))

#define fdatasync(...)	 except_sys(fdatasync(__VA_ARGS__))

#define fdetach(...)	 except_sys(fdetach(__VA_ARGS__))

#define finit_module(...)	 except_sys(finit_module(__VA_ARGS__))

#define flock(...)	 except_sys(flock(__VA_ARGS__))

#define fork(...)	 except_sys(fork(__VA_ARGS__))

#define free_hugepages(...)	 except_sys(free_hugepages(__VA_ARGS__))

#define fstat(...)	 except_sys(fstat(__VA_ARGS__))

#define fstat64(...)	 except_sys(fstat64(__VA_ARGS__))

#define fstatat(...)	 except_sys(fstatat(__VA_ARGS__))

#define fstatat64(...)	 except_sys(fstatat64(__VA_ARGS__))

#define fstatfs(...)	 except_sys(fstatfs(__VA_ARGS__))

#define fstatfs64(...)	 except_sys(fstatfs64(__VA_ARGS__))

#define fstatvfs(...)	 except_sys(fstatvfs(__VA_ARGS__))

#define fsync(...)	 except_sys(fsync(__VA_ARGS__))

#define ftruncate(...)	 except_sys(ftruncate(__VA_ARGS__))

#define ftruncate64(...)	 except_sys(ftruncate64(__VA_ARGS__))

#define futex(...)	 except_sys(futex(__VA_ARGS__))

#define futimesat(...)	 except_sys(futimesat(__VA_ARGS__))

#define getcontext(...)	 except_sys(getcontext(__VA_ARGS__))

#define getcpu(...)	 except_sys(getcpu(__VA_ARGS__))

#define getcwd(...)	 except_sys(getcwd(__VA_ARGS__))

#define getdents(...)	 except_sys(getdents(__VA_ARGS__))

#define getdents64(...)	 except_sys(getdents64(__VA_ARGS__))

#define getdomainname(...)	 except_sys(getdomainname(__VA_ARGS__))

#define getdtablesize(...)	 except_sys(getdtablesize(__VA_ARGS__))

#define getegid(...)	 except_sys(getegid(__VA_ARGS__))

#define getegid32(...)	 except_sys(getegid32(__VA_ARGS__))

#define geteuid(...)	 except_sys(geteuid(__VA_ARGS__))

#define geteuid32(...)	 except_sys(geteuid32(__VA_ARGS__))

#define getgid(...)	 except_sys(getgid(__VA_ARGS__))

#define getgid32(...)	 except_sys(getgid32(__VA_ARGS__))

#define getgroups(...)	 except_sys(getgroups(__VA_ARGS__))

#define getgroups32(...)	 except_sys(getgroups32(__VA_ARGS__))

#define gethostid(...)	 except_sys(gethostid(__VA_ARGS__))

#define gethostname(...)	 except_sys(gethostname(__VA_ARGS__))

#define getitimer(...)	 except_sys(getitimer(__VA_ARGS__))

#define get_kernel_syms(...)	 except_sys(get_kernel_syms(__VA_ARGS__))

#define get_mempolicy(...)	 except_sys(get_mempolicy(__VA_ARGS__))

#define getmsg(...)	 except_sys(getmsg(__VA_ARGS__))

#define getpagesize(...)	 except_sys(getpagesize(__VA_ARGS__))

#define getpeername(...)	 except_sys(getpeername(__VA_ARGS__))

#define getpgid(...)	 except_sys(getpgid(__VA_ARGS__))

#define getpgrp(...)	 except_sys(getpgrp(__VA_ARGS__))

#define getpid(...)	 except_sys(getpid(__VA_ARGS__))

#define getpmsg(...)	 except_sys(getpmsg(__VA_ARGS__))

#define getppid(...)	 except_sys(getppid(__VA_ARGS__))

#define getpriority(...)	 except_sys(getpriority(__VA_ARGS__))

#define getrandom(...)	 except_sys(getrandom(__VA_ARGS__))

#define getresgid(...)	 except_sys(getresgid(__VA_ARGS__))

#define getresgid32(...)	 except_sys(getresgid32(__VA_ARGS__))

#define getresuid(...)	 except_sys(getresuid(__VA_ARGS__))

#define getresuid32(...)	 except_sys(getresuid32(__VA_ARGS__))

#define getrlimit(...)	 except_sys(getrlimit(__VA_ARGS__))

#define get_robust_list(...)	 except_sys(get_robust_list(__VA_ARGS__))

#define getrusage(...)	 except_sys(getrusage(__VA_ARGS__))

#define getsid(...)	 except_sys(getsid(__VA_ARGS__))

#define getsockname(...)	 except_sys(getsockname(__VA_ARGS__))

#define getsockopt(...)	 except_sys(getsockopt(__VA_ARGS__))

#define get_thread_area(...)	 except_sys(get_thread_area(__VA_ARGS__))

#define gettid(...)	 except_sys(gettid(__VA_ARGS__))

#define gettimeofday(...)	 except_sys(gettimeofday(__VA_ARGS__))

#define getuid(...)	 except_sys(getuid(__VA_ARGS__))

#define getuid32(...)	 except_sys(getuid32(__VA_ARGS__))

#define getunwind(...)	 except_sys(getunwind(__VA_ARGS__))

#define gtty(...)	 except_sys(gtty(__VA_ARGS__))

#define idle(...)	 except_sys(idle(__VA_ARGS__))

#define inb(...)	 except_sys(inb(__VA_ARGS__))

#define inb_p(...)	 except_sys(inb_p(__VA_ARGS__))

#define init_module(...)	 except_sys(init_module(__VA_ARGS__))

#define inl(...)	 except_sys(inl(__VA_ARGS__))

#define inl_p(...)	 except_sys(inl_p(__VA_ARGS__))

#define inotify_add_watch(...)	 except_sys(inotify_add_watch(__VA_ARGS__))

#define inotify_init1(...)	 except_sys(inotify_init1(__VA_ARGS__))

#define inotify_init(...)	 except_sys(inotify_init(__VA_ARGS__))

#define inotify_rm_watch(...)	 except_sys(inotify_rm_watch(__VA_ARGS__))

#define insb(...)	 except_sys(insb(__VA_ARGS__))

#define insl(...)	 except_sys(insl(__VA_ARGS__))

#define insw(...)	 except_sys(insw(__VA_ARGS__))

#define intro(...)	 except_sys(intro(__VA_ARGS__))

#define inw(...)	 except_sys(inw(__VA_ARGS__))

#define inw_p(...)	 except_sys(inw_p(__VA_ARGS__))

#define io_cancel(...)	 except_sys(io_cancel(__VA_ARGS__))

#define ioctl(...)	 except_sys(ioctl(__VA_ARGS__))

#define ioctl_console(...)	 except_sys(ioctl_console(__VA_ARGS__))

#define ioctl_fat(...)	 except_sys(ioctl_fat(__VA_ARGS__))

#define ioctl_ficlone(...)	 except_sys(ioctl_ficlone(__VA_ARGS__))

#define ioctl_ficlonerange(...)	 except_sys(ioctl_ficlonerange(__VA_ARGS__))

#define ioctl_fideduperange(...)	 except_sys(ioctl_fideduperange(__VA_ARGS__))

#define ioctl_getfsmap(...)	 except_sys(ioctl_getfsmap(__VA_ARGS__))

#define ioctl_iflags(...)	 except_sys(ioctl_iflags(__VA_ARGS__))

#define ioctl_list(...)	 except_sys(ioctl_list(__VA_ARGS__))

#define ioctl_ns(...)	 except_sys(ioctl_ns(__VA_ARGS__))

#define ioctl_tty(...)	 except_sys(ioctl_tty(__VA_ARGS__))

#define ioctl_userfaultfd(...)	 except_sys(ioctl_userfaultfd(__VA_ARGS__))

#define io_destroy(...)	 except_sys(io_destroy(__VA_ARGS__))

#define io_getevents(...)	 except_sys(io_getevents(__VA_ARGS__))

#define ioperm(...)	 except_sys(ioperm(__VA_ARGS__))

#define iopl(...)	 except_sys(iopl(__VA_ARGS__))

#define ioprio_get(...)	 except_sys(ioprio_get(__VA_ARGS__))

#define ioprio_set(...)	 except_sys(ioprio_set(__VA_ARGS__))

#define io_setup(...)	 except_sys(io_setup(__VA_ARGS__))

#define io_submit(...)	 except_sys(io_submit(__VA_ARGS__))

#define ipc(...)	 except_sys(ipc(__VA_ARGS__))

#define isastream(...)	 except_sys(isastream(__VA_ARGS__))

#define kcmp(...)	 except_sys(kcmp(__VA_ARGS__))

#define kexec_file_load(...)	 except_sys(kexec_file_load(__VA_ARGS__))

#define kexec_load(...)	 except_sys(kexec_load(__VA_ARGS__))

#define keyctl(...)	 except_sys(keyctl(__VA_ARGS__))

#define kill(...)	 except_sys(kill(__VA_ARGS__))

#define killpg(...)	 except_sys(killpg(__VA_ARGS__))

#define lchown(...)	 except_sys(lchown(__VA_ARGS__))

#define lchown32(...)	 except_sys(lchown32(__VA_ARGS__))

#define link(...)	 except_sys(link(__VA_ARGS__))

#define linkat(...)	 except_sys(linkat(__VA_ARGS__))

#define listen(...)	 except_sys(listen(__VA_ARGS__))

#define _llseek(...)	 except_sys(_llseek(__VA_ARGS__))

#define llseek(...)	 except_sys(llseek(__VA_ARGS__))

#define lock(...)	 except_sys(lock(__VA_ARGS__))

#define lookup_dcookie(...)	 except_sys(lookup_dcookie(__VA_ARGS__))

#define lseek(...)	 except_sys(lseek(__VA_ARGS__))

#define lstat(...)	 except_sys(lstat(__VA_ARGS__))

#define lstat64(...)	 except_sys(lstat64(__VA_ARGS__))

#define madvise1(...)	 except_sys(madvise1(__VA_ARGS__))

#define madvise(...)	 except_sys(madvise(__VA_ARGS__))

#define mbind(...)	 except_sys(mbind(__VA_ARGS__))

#define membarrier(...)	 except_sys(membarrier(__VA_ARGS__))

#define memfd_create(...)	 except_sys(memfd_create(__VA_ARGS__))

#define migrate_pages(...)	 except_sys(migrate_pages(__VA_ARGS__))

#define mincore(...)	 except_sys(mincore(__VA_ARGS__))

#define mkdir(...)	 except_sys(mkdir(__VA_ARGS__))

#define mkdirat(...)	 except_sys(mkdirat(__VA_ARGS__))

#define mknod(...)	 except_sys(mknod(__VA_ARGS__))

#define mknodat(...)	 except_sys(mknodat(__VA_ARGS__))

#define mlock2(...)	 except_sys(mlock2(__VA_ARGS__))

#define mlock(...)	 except_sys(mlock(__VA_ARGS__))

#define mlockall(...)	 except_sys(mlockall(__VA_ARGS__))

#define mmap2(...)	 except_sys(mmap2(__VA_ARGS__))

#define mmap(...)	 except_sys(mmap(__VA_ARGS__))

#define modify_ldt(...)	 except_sys(modify_ldt(__VA_ARGS__))

#define mount(...)	 except_sys(mount(__VA_ARGS__))

#define move_pages(...)	 except_sys(move_pages(__VA_ARGS__))

#define mprotect(...)	 except_sys(mprotect(__VA_ARGS__))

#define mpx(...)	 except_sys(mpx(__VA_ARGS__))

#define mq_getsetattr(...)	 except_sys(mq_getsetattr(__VA_ARGS__))

#define mq_notify(...)	 except_sys(mq_notify(__VA_ARGS__))

#define mq_open(...)	 except_sys(mq_open(__VA_ARGS__))

#define mq_timedreceive(...)	 except_sys(mq_timedreceive(__VA_ARGS__))

#define mq_timedsend(...)	 except_sys(mq_timedsend(__VA_ARGS__))

#define mq_unlink(...)	 except_sys(mq_unlink(__VA_ARGS__))

#define mremap(...)	 except_sys(mremap(__VA_ARGS__))

#define msgctl(...)	 except_sys(msgctl(__VA_ARGS__))

#define msgget(...)	 except_sys(msgget(__VA_ARGS__))

#define msgop(...)	 except_sys(msgop(__VA_ARGS__))

#define msgrcv(...)	 except_sys(msgrcv(__VA_ARGS__))

#define msgsnd(...)	 except_sys(msgsnd(__VA_ARGS__))

#define msync(...)	 except_sys(msync(__VA_ARGS__))

#define munlock(...)	 except_sys(munlock(__VA_ARGS__))

#define munlockall(...)	 except_sys(munlockall(__VA_ARGS__))

#define munmap(...)	 except_sys(munmap(__VA_ARGS__))

#define name_to_handle_at(...)	 except_sys(name_to_handle_at(__VA_ARGS__))

#define nanosleep(...)	 except_sys(nanosleep(__VA_ARGS__))

#define newfstatat(...)	 except_sys(newfstatat(__VA_ARGS__))

#define _newselect(...)	 except_sys(_newselect(__VA_ARGS__))

#define nfsservctl(...)	 except_sys(nfsservctl(__VA_ARGS__))

#define nice(...)	 except_sys(nice(__VA_ARGS__))

#define oldfstat(...)	 except_sys(oldfstat(__VA_ARGS__))

#define oldlstat(...)	 except_sys(oldlstat(__VA_ARGS__))

#define oldolduname(...)	 except_sys(oldolduname(__VA_ARGS__))

#define oldstat(...)	 except_sys(oldstat(__VA_ARGS__))

#define olduname(...)	 except_sys(olduname(__VA_ARGS__))

#define open(...)	 except_sys(open(__VA_ARGS__))

#define openat(...)	 except_sys(openat(__VA_ARGS__))

#define open_by_handle_at(...)	 except_sys(open_by_handle_at(__VA_ARGS__))

#define outb(...)	 except_sys(outb(__VA_ARGS__))

#define outb_p(...)	 except_sys(outb_p(__VA_ARGS__))

#define outl(...)	 except_sys(outl(__VA_ARGS__))

#define outl_p(...)	 except_sys(outl_p(__VA_ARGS__))

#define outsb(...)	 except_sys(outsb(__VA_ARGS__))

#define outsl(...)	 except_sys(outsl(__VA_ARGS__))

#define outsw(...)	 except_sys(outsw(__VA_ARGS__))

#define outw(...)	 except_sys(outw(__VA_ARGS__))

#define outw_p(...)	 except_sys(outw_p(__VA_ARGS__))

#define pause(...)	 except_sys(pause(__VA_ARGS__))

#define pciconfig_iobase(...)	 except_sys(pciconfig_iobase(__VA_ARGS__))

#define pciconfig_read(...)	 except_sys(pciconfig_read(__VA_ARGS__))

#define pciconfig_write(...)	 except_sys(pciconfig_write(__VA_ARGS__))

#define perf_event_open(...)	 except_sys(perf_event_open(__VA_ARGS__))

#define perfmonctl(...)	 except_sys(perfmonctl(__VA_ARGS__))

#define personality(...)	 except_sys(personality(__VA_ARGS__))

#define phys(...)	 except_sys(phys(__VA_ARGS__))

#define pipe2(...)	 except_sys(pipe2(__VA_ARGS__))

#define pipe(...)	 except_sys(pipe(__VA_ARGS__))

#define pivot_root(...)	 except_sys(pivot_root(__VA_ARGS__))

#define pkey_alloc(...)	 except_sys(pkey_alloc(__VA_ARGS__))

#define pkey_free(...)	 except_sys(pkey_free(__VA_ARGS__))

#define pkey_mprotect(...)	 except_sys(pkey_mprotect(__VA_ARGS__))

#define poll(...)	 except_sys(poll(__VA_ARGS__))

#define posix_fadvise(...)	 except_sys(posix_fadvise(__VA_ARGS__))

#define ppoll(...)	 except_sys(ppoll(__VA_ARGS__))

#define prctl(...)	 except_sys(prctl(__VA_ARGS__))

#define pread(...)	 except_sys(pread(__VA_ARGS__))

#define pread64(...)	 except_sys(pread64(__VA_ARGS__))

#define preadv2(...)	 except_sys(preadv2(__VA_ARGS__))

#define preadv(...)	 except_sys(preadv(__VA_ARGS__))

#define prlimit(...)	 except_sys(prlimit(__VA_ARGS__))

#define prlimit64(...)	 except_sys(prlimit64(__VA_ARGS__))

#define process_vm_readv(...)	 except_sys(process_vm_readv(__VA_ARGS__))

#define process_vm_writev(...)	 except_sys(process_vm_writev(__VA_ARGS__))

#define prof(...)	 except_sys(prof(__VA_ARGS__))

#define pselect(...)	 except_sys(pselect(__VA_ARGS__))

#define pselect6(...)	 except_sys(pselect6(__VA_ARGS__))

#define ptrace(...)	 except_sys(ptrace(__VA_ARGS__))

#define putmsg(...)	 except_sys(putmsg(__VA_ARGS__))

#define putpmsg(...)	 except_sys(putpmsg(__VA_ARGS__))

#define pwrite(...)	 except_sys(pwrite(__VA_ARGS__))

#define pwrite64(...)	 except_sys(pwrite64(__VA_ARGS__))

#define pwritev2(...)	 except_sys(pwritev2(__VA_ARGS__))

#define pwritev(...)	 except_sys(pwritev(__VA_ARGS__))

#define query_module(...)	 except_sys(query_module(__VA_ARGS__))

#define quotactl(...)	 except_sys(quotactl(__VA_ARGS__))

#define read(...)	 except_sys(read(__VA_ARGS__))

#define readahead(...)	 except_sys(readahead(__VA_ARGS__))

#define readdir(...)	 except_sys(readdir(__VA_ARGS__))

#define readlink(...)	 except_sys(readlink(__VA_ARGS__))

#define readlinkat(...)	 except_sys(readlinkat(__VA_ARGS__))

#define readv(...)	 except_sys(readv(__VA_ARGS__))

#define reboot(...)	 except_sys(reboot(__VA_ARGS__))

#define recv(...)	 except_sys(recv(__VA_ARGS__))

#define recvfrom(...)	 except_sys(recvfrom(__VA_ARGS__))

#define recvmmsg(...)	 except_sys(recvmmsg(__VA_ARGS__))

#define recvmsg(...)	 except_sys(recvmsg(__VA_ARGS__))

#define remap_file_pages(...)	 except_sys(remap_file_pages(__VA_ARGS__))

#define rename(...)	 except_sys(rename(__VA_ARGS__))

#define renameat2(...)	 except_sys(renameat2(__VA_ARGS__))

#define renameat(...)	 except_sys(renameat(__VA_ARGS__))

#define request_key(...)	 except_sys(request_key(__VA_ARGS__))

#define restart_syscall(...)	 except_sys(restart_syscall(__VA_ARGS__))

#define rmdir(...)	 except_sys(rmdir(__VA_ARGS__))

#define rt_sigaction(...)	 except_sys(rt_sigaction(__VA_ARGS__))

#define rt_sigpending(...)	 except_sys(rt_sigpending(__VA_ARGS__))

#define rt_sigprocmask(...)	 except_sys(rt_sigprocmask(__VA_ARGS__))

#define rt_sigqueueinfo(...)	 except_sys(rt_sigqueueinfo(__VA_ARGS__))

#define rt_sigreturn(...)	 except_sys(rt_sigreturn(__VA_ARGS__))

#define rt_sigsuspend(...)	 except_sys(rt_sigsuspend(__VA_ARGS__))

#define rt_sigtimedwait(...)	 except_sys(rt_sigtimedwait(__VA_ARGS__))

#define rt_tgsigqueueinfo(...)	 except_sys(rt_tgsigqueueinfo(__VA_ARGS__))

#define s390_pci_mmio_read(...)	 except_sys(s390_pci_mmio_read(__VA_ARGS__))

#define s390_pci_mmio_write(...)	 except_sys(s390_pci_mmio_write(__VA_ARGS__))

#define s390_runtime_instr(...)	 except_sys(s390_runtime_instr(__VA_ARGS__))

#define s390_sthyi(...)	 except_sys(s390_sthyi(__VA_ARGS__))

#define sbrk(...)	 except_sys(sbrk(__VA_ARGS__))

#define sched_getaffinity(...)	 except_sys(sched_getaffinity(__VA_ARGS__))

#define sched_getattr(...)	 except_sys(sched_getattr(__VA_ARGS__))

#define sched_getparam(...)	 except_sys(sched_getparam(__VA_ARGS__))

#define sched_get_priority_max(...)	 except_sys(sched_get_priority_max(__VA_ARGS__))

#define sched_get_priority_min(...)	 except_sys(sched_get_priority_min(__VA_ARGS__))

#define sched_getscheduler(...)	 except_sys(sched_getscheduler(__VA_ARGS__))

#define sched_rr_get_interval(...)	 except_sys(sched_rr_get_interval(__VA_ARGS__))

#define sched_setaffinity(...)	 except_sys(sched_setaffinity(__VA_ARGS__))

#define sched_setattr(...)	 except_sys(sched_setattr(__VA_ARGS__))

#define sched_setparam(...)	 except_sys(sched_setparam(__VA_ARGS__))

#define sched_setscheduler(...)	 except_sys(sched_setscheduler(__VA_ARGS__))

#define sched_yield(...)	 except_sys(sched_yield(__VA_ARGS__))

#define seccomp(...)	 except_sys(seccomp(__VA_ARGS__))

#define security(...)	 except_sys(security(__VA_ARGS__))

#define select(...)	 except_sys(select(__VA_ARGS__))

#define select_tut(...)	 except_sys(select_tut(__VA_ARGS__))

#define semctl(...)	 except_sys(semctl(__VA_ARGS__))

#define semget(...)	 except_sys(semget(__VA_ARGS__))

#define semop(...)	 except_sys(semop(__VA_ARGS__))

#define semtimedop(...)	 except_sys(semtimedop(__VA_ARGS__))

#define send(...)	 except_sys(send(__VA_ARGS__))

#define sendfile(...)	 except_sys(sendfile(__VA_ARGS__))

#define sendfile64(...)	 except_sys(sendfile64(__VA_ARGS__))

#define sendmmsg(...)	 except_sys(sendmmsg(__VA_ARGS__))

#define sendmsg(...)	 except_sys(sendmsg(__VA_ARGS__))

#define sendto(...)	 except_sys(sendto(__VA_ARGS__))

#define setcontext(...)	 except_sys(setcontext(__VA_ARGS__))

#define setdomainname(...)	 except_sys(setdomainname(__VA_ARGS__))

#define setegid(...)	 except_sys(setegid(__VA_ARGS__))

#define seteuid(...)	 except_sys(seteuid(__VA_ARGS__))

#define setfsgid(...)	 except_sys(setfsgid(__VA_ARGS__))

#define setfsgid32(...)	 except_sys(setfsgid32(__VA_ARGS__))

#define setfsuid(...)	 except_sys(setfsuid(__VA_ARGS__))

#define setfsuid32(...)	 except_sys(setfsuid32(__VA_ARGS__))

#define setgid(...)	 except_sys(setgid(__VA_ARGS__))

#define setgid32(...)	 except_sys(setgid32(__VA_ARGS__))

#define setgroups(...)	 except_sys(setgroups(__VA_ARGS__))

#define setgroups32(...)	 except_sys(setgroups32(__VA_ARGS__))

#define sethostid(...)	 except_sys(sethostid(__VA_ARGS__))

#define sethostname(...)	 except_sys(sethostname(__VA_ARGS__))

#define setitimer(...)	 except_sys(setitimer(__VA_ARGS__))

#define set_mempolicy(...)	 except_sys(set_mempolicy(__VA_ARGS__))

#define setns(...)	 except_sys(setns(__VA_ARGS__))

#define setpgid(...)	 except_sys(setpgid(__VA_ARGS__))

#define setpgrp(...)	 except_sys(setpgrp(__VA_ARGS__))

#define setpriority(...)	 except_sys(setpriority(__VA_ARGS__))

#define setregid(...)	 except_sys(setregid(__VA_ARGS__))

#define setregid32(...)	 except_sys(setregid32(__VA_ARGS__))

#define setresgid(...)	 except_sys(setresgid(__VA_ARGS__))

#define setresgid32(...)	 except_sys(setresgid32(__VA_ARGS__))

#define setresuid(...)	 except_sys(setresuid(__VA_ARGS__))

#define setresuid32(...)	 except_sys(setresuid32(__VA_ARGS__))

#define setreuid(...)	 except_sys(setreuid(__VA_ARGS__))

#define setreuid32(...)	 except_sys(setreuid32(__VA_ARGS__))

#define setrlimit(...)	 except_sys(setrlimit(__VA_ARGS__))

#define set_robust_list(...)	 except_sys(set_robust_list(__VA_ARGS__))

#define setsid(...)	 except_sys(setsid(__VA_ARGS__))

#define setsockopt(...)	 except_sys(setsockopt(__VA_ARGS__))

#define set_thread_area(...)	 except_sys(set_thread_area(__VA_ARGS__))

#define set_tid_address(...)	 except_sys(set_tid_address(__VA_ARGS__))

#define settimeofday(...)	 except_sys(settimeofday(__VA_ARGS__))

#define setuid(...)	 except_sys(setuid(__VA_ARGS__))

#define setuid32(...)	 except_sys(setuid32(__VA_ARGS__))

#define setup(...)	 except_sys(setup(__VA_ARGS__))

#define sgetmask(...)	 except_sys(sgetmask(__VA_ARGS__))

#define shmat(...)	 except_sys(shmat(__VA_ARGS__))

#define shmctl(...)	 except_sys(shmctl(__VA_ARGS__))

#define shmdt(...)	 except_sys(shmdt(__VA_ARGS__))

#define shmget(...)	 except_sys(shmget(__VA_ARGS__))

#define shmop(...)	 except_sys(shmop(__VA_ARGS__))

#define shutdown(...)	 except_sys(shutdown(__VA_ARGS__))

#define sigaction(...)	 except_sys(sigaction(__VA_ARGS__))

#define sigaltstack(...)	 except_sys(sigaltstack(__VA_ARGS__))

#define signal(...)	 except_sys(signal(__VA_ARGS__))

#define signalfd(...)	 except_sys(signalfd(__VA_ARGS__))

#define signalfd4(...)	 except_sys(signalfd4(__VA_ARGS__))

#define sigpending(...)	 except_sys(sigpending(__VA_ARGS__))

#define sigprocmask(...)	 except_sys(sigprocmask(__VA_ARGS__))

#define sigqueue(...)	 except_sys(sigqueue(__VA_ARGS__))

#define sigreturn(...)	 except_sys(sigreturn(__VA_ARGS__))

#define sigsuspend(...)	 except_sys(sigsuspend(__VA_ARGS__))

#define sigtimedwait(...)	 except_sys(sigtimedwait(__VA_ARGS__))

#define sigwaitinfo(...)	 except_sys(sigwaitinfo(__VA_ARGS__))

#define socket(...)	 except_sys(socket(__VA_ARGS__))

#define socketcall(...)	 except_sys(socketcall(__VA_ARGS__))

#define socketpair(...)	 except_sys(socketpair(__VA_ARGS__))

#define splice(...)	 except_sys(splice(__VA_ARGS__))

#define spu_create(...)	 except_sys(spu_create(__VA_ARGS__))

#define spu_run(...)	 except_sys(spu_run(__VA_ARGS__))

#define ssetmask(...)	 except_sys(ssetmask(__VA_ARGS__))

#define stat(...)	 except_sys(stat(__VA_ARGS__))

#define stat64(...)	 except_sys(stat64(__VA_ARGS__))

#define statfs(...)	 except_sys(statfs(__VA_ARGS__))

#define statfs64(...)	 except_sys(statfs64(__VA_ARGS__))

#define statvfs(...)	 except_sys(statvfs(__VA_ARGS__))

#define statx(...)	 except_sys(statx(__VA_ARGS__))

#define stime(...)	 except_sys(stime(__VA_ARGS__))

#define stty(...)	 except_sys(stty(__VA_ARGS__))

#define subpage_prot(...)	 except_sys(subpage_prot(__VA_ARGS__))

#define swapoff(...)	 except_sys(swapoff(__VA_ARGS__))

#define swapon(...)	 except_sys(swapon(__VA_ARGS__))

#define symlink(...)	 except_sys(symlink(__VA_ARGS__))

#define symlinkat(...)	 except_sys(symlinkat(__VA_ARGS__))

#define sync(...)	 except_sys(sync(__VA_ARGS__))

#define sync_file_range2(...)	 except_sys(sync_file_range2(__VA_ARGS__))

#define sync_file_range(...)	 except_sys(sync_file_range(__VA_ARGS__))

#define syncfs(...)	 except_sys(syncfs(__VA_ARGS__))

#define _syscall(...)	 except_sys(_syscall(__VA_ARGS__))

#define syscall(...)	 except_sys(syscall(__VA_ARGS__))

#define syscalls(...)	 except_sys(syscalls(__VA_ARGS__))

#define _sysctl(...)	 except_sys(_sysctl(__VA_ARGS__))

#define sysctl(...)	 except_sys(sysctl(__VA_ARGS__))

#define sysfs(...)	 except_sys(sysfs(__VA_ARGS__))

#define sysinfo(...)	 except_sys(sysinfo(__VA_ARGS__))

#define syslog(...)	 except_sys(syslog(__VA_ARGS__))

#define tee(...)	 except_sys(tee(__VA_ARGS__))

#define tgkill(...)	 except_sys(tgkill(__VA_ARGS__))

#define time(...)	 except_sys(time(__VA_ARGS__))

#define timer_create(...)	 except_sys(timer_create(__VA_ARGS__))

#define timer_delete(...)	 except_sys(timer_delete(__VA_ARGS__))

#define timerfd_create(...)	 except_sys(timerfd_create(__VA_ARGS__))

#define timerfd_gettime(...)	 except_sys(timerfd_gettime(__VA_ARGS__))

#define timerfd_settime(...)	 except_sys(timerfd_settime(__VA_ARGS__))

#define timer_getoverrun(...)	 except_sys(timer_getoverrun(__VA_ARGS__))

#define timer_gettime(...)	 except_sys(timer_gettime(__VA_ARGS__))

#define timer_settime(...)	 except_sys(timer_settime(__VA_ARGS__))

#define times(...)	 except_sys(times(__VA_ARGS__))

#define tkill(...)	 except_sys(tkill(__VA_ARGS__))

#define truncate(...)	 except_sys(truncate(__VA_ARGS__))

#define truncate64(...)	 except_sys(truncate64(__VA_ARGS__))

#define tuxcall(...)	 except_sys(tuxcall(__VA_ARGS__))

#define ugetrlimit(...)	 except_sys(ugetrlimit(__VA_ARGS__))

#define umask(...)	 except_sys(umask(__VA_ARGS__))

#define umount2(...)	 except_sys(umount2(__VA_ARGS__))

#define umount(...)	 except_sys(umount(__VA_ARGS__))

#define uname(...)	 except_sys(uname(__VA_ARGS__))

#define unimplemented(...)	 except_sys(unimplemented(__VA_ARGS__))

#define unlink(...)	 except_sys(unlink(__VA_ARGS__))

#define unlinkat(...)	 except_sys(unlinkat(__VA_ARGS__))

#define unshare(...)	 except_sys(unshare(__VA_ARGS__))

#define uselib(...)	 except_sys(uselib(__VA_ARGS__))

#define userfaultfd(...)	 except_sys(userfaultfd(__VA_ARGS__))

#define ustat(...)	 except_sys(ustat(__VA_ARGS__))

#define utime(...)	 except_sys(utime(__VA_ARGS__))

#define utimensat(...)	 except_sys(utimensat(__VA_ARGS__))

#define utimes(...)	 except_sys(utimes(__VA_ARGS__))

#define vfork(...)	 except_sys(vfork(__VA_ARGS__))

#define vhangup(...)	 except_sys(vhangup(__VA_ARGS__))

#define vm86(...)	 except_sys(vm86(__VA_ARGS__))

#define vm86old(...)	 except_sys(vm86old(__VA_ARGS__))

#define vmsplice(...)	 except_sys(vmsplice(__VA_ARGS__))

#define vserver(...)	 except_sys(vserver(__VA_ARGS__))

#define wait(...)	 except_sys(wait(__VA_ARGS__))

#define wait3(...)	 except_sys(wait3(__VA_ARGS__))

#define wait4(...)	 except_sys(wait4(__VA_ARGS__))

#define waitid(...)	 except_sys(waitid(__VA_ARGS__))

#define waitpid(...)	 except_sys(waitpid(__VA_ARGS__))

#define write(...)	 except_sys(write(__VA_ARGS__))

#define writev(...)	 except_sys(writev(__VA_ARGS__))

