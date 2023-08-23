#ifndef _KLNK_H
#define _KLNK_H

#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/vres.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <linux/hugetlb.h>
#include <linux/version.h>
#include <linux/fs_struct.h>
#include <linux/vres.h>

#define PATH_ROOT      "/vhub/root"
#define PATH_VMAP      "/vhub/mnt/vmap"
#define PATH_MATEFS    "/vhub/mnt/matefs"
#define PATH_KLNK      "/vhub/mnt/klnk/io"

#define KLNK_IO_MAX    8192
#define KLNK_PATH_MAX  128

#define KLNK_DEBUG_MSG
#define KLNK_DEBUG_SEM
#define KLNK_DEBUG_SHM

#define klnk_log(fmt, ...) printk("%s@%d: " fmt "\n", __func__, current->gpid, ##__VA_ARGS__)

#ifdef KLNK_DEBUG_MSG
#define klnk_msg_log klnk_log
#else
#define klnk_msg_log(...) do {} while (0)
#endif

#ifdef KLNK_DEBUG_SEM
#define klnk_sem_log klnk_log
#else
#define klnk_sem_log(...) do {} while (0)
#endif

#ifdef KLNK_DEBUG_SHM
#define klnk_shm_log klnk_log
#else
#define klnk_shm_log(...) do {} while (0)
#endif

typedef struct klnk_request {
	vres_cls_t cls;
	vres_key_t key;
	vres_op_t op;
	vres_id_t id;
	vres_val_t val1;
	vres_val_t val2;
	void *buf;
	size_t inlen;
	size_t outlen;
} klnk_request_t;

static inline void *klnk_malloc(size_t size)
{
	int order = get_order(size);
	unsigned long ret = __get_free_pages(GFP_KERNEL, order);

	if (ret) {
		int i;
		int nr_pages = 1 << order;
		unsigned long addr = ret;

		for (i = 0; i < nr_pages; i++) {
			SetPageReserved(virt_to_page(addr));
			addr += PAGE_SIZE;
		}
	}
	return (void *)ret;
}

static inline void klnk_free(void *ptr, size_t size)
{
	unsigned long addr = (unsigned long)ptr;

	if (addr) {
		int i;
		int order = get_order(size);
		int nr_pages = 1 << order;

		for (i = 0; i < nr_pages; i++) {
			ClearPageReserved(virt_to_page(addr));
			addr += PAGE_SIZE;
		}
		free_pages((unsigned long)ptr, order);
	}
}

static inline pid_t klnk_get_gpid(struct task_struct *tsk)
{
	return tsk->gpid;
}

static inline void klnk_set_gpid(struct task_struct *tsk, pid_t id)
{
	tsk->gpid = id;
}

static inline int klnk_is_global(struct task_struct *tsk)
{
	return tsk->gpid > 0;
}

static inline int klnk_can_enter(struct task_struct *tsk)
{
	char path[VRES_PATH_MAX];
	struct path *pwd = &tsk->fs->pwd;
	char *name = d_path(pwd, path, VRES_PATH_MAX);

	if (IS_ERR(name))
		return 0;

	if (!strncmp(name, PATH_ROOT, strlen(PATH_ROOT)))
		return 1;
	else
		return 0;
}

static inline pte_t *klnk_get_pte(struct mm_struct *mm, unsigned long address, spinlock_t **ptlp)
{
	pte_t *pte;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	spinlock_t *ptl = NULL;

	pgd = pgd_offset(mm, address);
	if (unlikely(pgd_none(*pgd)))
		return NULL;

	p4d = p4d_offset(pgd, address);
	if (unlikely(p4d_none(*p4d)))
		return NULL;

	pud = pud_offset(p4d, address);
	if (unlikely(pud_none(*pud)))
		return NULL;

	pmd = pmd_offset(pud, address);
	if (unlikely(pmd_none(*pmd)))
		return NULL;

	pte = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (unlikely(!pte_present(*pte))) {
		pte_unmap_unlock(pte, ptl);
		return NULL;
	}
	*ptlp = ptl;
	return pte;
}

static inline void klnk_put_pte(pte_t *ptep, spinlock_t *ptl)
{
	pte_unmap_unlock(ptep, ptl);
}

int klnk_load_vma(struct vm_area_struct *vma);

static inline int klnk_request(vres_cls_t cls,
                               vres_key_t key,
                               vres_op_t op,
                               vres_id_t id,
                               vres_val_t val1,
                               vres_val_t val2,
                               void *buf,
                               size_t inlen,
                               size_t outlen)
{
	ssize_t ret;
	loff_t offset = 0;
	static struct file *filp = NULL;
	void *p = buf ? (void *)__pa(buf) : buf;
	const ssize_t sz = sizeof(klnk_request_t);
	klnk_request_t req = {
		cls: cls,
		key: key,
		op: op,
		id: id,
		val1: val1,
		val2: val2,
		buf: p,
		inlen: inlen,
		outlen: outlen
	};
	if (!filp) {
		filp = filp_open(PATH_KLNK, O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
		if (IS_ERR(filp)) {
			klnk_log("failed to open %s", PATH_KLNK);
			return PTR_ERR(filp);
		}
	}
	ret = kernel_write(filp, (char *)&req, sz, &offset);
	if (ret == sz)
		return 0;
	else {
		klnk_log("failed to send request, ret=%ld", ret);
		return -EINVAL;
	}
}

static inline int klnk_is_vmap(struct file *file)
{
	char *buf;
	int ret = 0;

	if (!file)
		return ret;

	buf = (char *)kmalloc(KLNK_PATH_MAX, GFP_KERNEL);
	if (buf) {
		char *name;

		name = d_path(&file->f_path, buf, KLNK_PATH_MAX);
		if (!IS_ERR(name)) {
			const int len = strlen(PATH_VMAP);

			if (!strncmp(name, PATH_VMAP, len))
				if ((strlen(name) == len) || (name[len] == '/'))
					ret = 1;
		}
		kfree(buf);
	}
	return ret;
}

static inline int klnk_migrate(struct filename *filename)
{
	int ret;
	char *buf;
	vres_mig_arg_t *arg;
	const char *path = filename->name;
	pid_t gpid = klnk_get_gpid(current);
	size_t buflen = sizeof(vres_mig_arg_t);

	if (strlen(path) >= VRES_PATH_MAX) {
		klnk_log("invalid path");
		return -EINVAL;
	}

	buf = klnk_malloc(buflen);
	if (!buf) {
		klnk_log("no memory");
		return -ENOMEM;
	}

	arg = (vres_mig_arg_t *)buf;
	strcpy(arg->path, path);
	ret = klnk_request(VRES_CLS_TSK, gpid, VRES_OP_MIGRATE, gpid, 0, 0, buf, buflen, 0);
	if (!ret)
		ret = -EINTR;
	else if (-EAGAIN == ret)
		filename->name = PATH_MATEFS;
	klnk_free(buf, buflen);
	klnk_log("path=%s", path);
	return ret;
}

static inline struct file *klnk_filp_open(struct filename *filename)
{
	if (klnk_is_global(current))
		return ERR_PTR(klnk_migrate(filename));
	else
		return ERR_PTR(-ENOENT);
}

#endif
