#include <linux/sysfs.h>
#include <linux/userfaultfd_k.h>
#include <linux/kthread.h>
#include <linux/inet.h>
#include <rdma/rdma_cm.h>

/* use this for timing measurements on PPC64 */
#define MFSPR(_x) __asm__ volatile ("mfspr %0, 268" : "=r" (_x))

/* 
There is a list of IB devices known in the system - maintained by the module by
receiving notifications on device add/removal from the IB subsystem.
The user selects a pid through sysfs to serve page faults. At that point, a queue
pair is opened for it.
There is an RDMA queue pair per address space (pid). Each queue pair is associated
   with exactly one IB device.  */

#define RDMA_RESOLVE_TIMEOUT 2000
#define RDMA_XCHNG_BUF_SIZE 16
#define RDMA_MAX_OUTSTANDING_READS 1

enum link_state
{
   LINK_STATE_UNINIT,
   LINK_STATE_INIT,
   LINK_STATE_ADDR_RESOLVED,
   LINK_STATE_ROUTE_RESOLVED,
   LINK_STATE_READY,
   LINK_STATE_CONNECTED,
};

typedef struct rpf_link
{
   enum link_state state;
   unsigned int rkey;               /* RDMA remote key */
   struct completion cm_done;       /* connection manager wait object */
   struct completion cq_done;       /* completion queue wait object */
   struct userfaultfd_ctx *uf_ctx;  /* uffd context */
   struct rdma_cm_id *cm_id;        /* Connection manager */
   struct ib_pd *pd;                /* protection domain */
   struct ib_cq *cq;                /* completion queue */
   void* page_in;                   /* page sized buffer described by mr_page */
   dma_addr_t recv_msg_dma;         /* memory region to hold incoming page */
   char* recv_msg;
} rpf_link;

struct ib_device_entry {
   struct list_head list;
   struct ib_device_entry *next;
   struct ib_device *dev;
};

struct ib_device_list {
   struct list_head list;
   spinlock_t lock;
};

typedef struct rpf_object
{
   struct kobject* sysfsroot;
   unsigned int active_pid;               // which pid are we currently serving page faults for
   struct task_struct *handler;           // the handler thread
   unsigned int rhost_ip;
   unsigned short rhost_port;
   unsigned int rkey;                     // remote key for RDMA READ 
   rpf_link link;
} rpf_object;

/**** RDMA ****/

/* used to receive memory region details from the server */
struct mr_context {
	void		       *addr;
	uint32_t		rkey;
};

// some forward declarations to keep things organized
// must be added to Documentation/ABI
ssize_t show_readme(struct kobject *kobj, struct kobj_attribute *attr, char *buff);
ssize_t show_pid(struct kobject *kobj, struct kobj_attribute *attr, char *buff);
ssize_t store_pid(struct kobject *kobj, struct kobj_attribute *attr, const char *buff, size_t size);
ssize_t show_server(struct kobject *kobj, struct kobj_attribute *attr, char *buff);
ssize_t store_server(struct kobject *kobj, struct kobj_attribute *attr, const char *buff, size_t size);
ssize_t show_port(struct kobject *kobj, struct kobj_attribute *attr, char *buff);
ssize_t store_port(struct kobject *kobj, struct kobj_attribute *attr, const char *buff, size_t size);
void on_device_add(struct ib_device *dev);
void on_device_remove(struct ib_device *dev, void *client_data);

// the one and only global object
static rpf_object rpf;

static struct ib_client rpf_ib_client = {
	.name	= "RPF_IBClient",
	.add	= on_device_add,
	.remove = on_device_remove,
};

struct ib_device_list ib_device_list = {
	.lock = __SPIN_LOCK_UNLOCKED(ib_device_list.lock),
	.list = LIST_HEAD_INIT(ib_device_list.list),
};

static const char help_text[] = 
"Use the server file to set the IP address or host name of the remote server that will be serving the page faults\n"
"Use the port file to set the port number of the listening RDMA connection on the server\n"
"Use the pid file to set the process ID of the application that will be generating page faults\n";

/* some sysfs stuff */
struct kobj_attribute readme_attr = __ATTR(readme, 0444, show_readme, NULL);
struct kobj_attribute pid_attr = __ATTR(pid, 0644, show_pid, store_pid);
struct kobj_attribute server_attr = __ATTR(rhost, 0644, show_server, store_server);
struct kobj_attribute port_attr = __ATTR(rport, 0644, show_port, store_port);

struct attribute *rpf_attributes[] = {
   &readme_attr.attr,
   &pid_attr.attr,
   &server_attr.attr,
   &port_attr.attr,
   NULL
};

struct attribute_group rpf_attr_group = {
	.attrs = rpf_attributes,
};

/************* RDMA *******************/
void on_device_add(struct ib_device *dev)
{
   struct ib_device_entry *entry = kzalloc(sizeof(struct ib_device_entry), GFP_KERNEL);

   if (!entry) {
      printk("RPF: error allocating memory in on_device_add\n");
      return;
   }

   entry->dev = dev;
	ib_set_client_data(dev, &rpf_ib_client, entry);

   /* add it to our list of devices */
	spin_lock(&ib_device_list.lock);
	list_add_tail(&entry->list, &ib_device_list.list);
	spin_unlock(&ib_device_list.lock);
}

void on_device_remove(struct ib_device *dev, void *client_data)
{
	struct ib_device_entry *entry = ib_get_client_data(dev, &rpf_ib_client);
	ib_set_client_data(dev, &rpf_ib_client, NULL);

   /* remove it from the list */
	spin_lock(&ib_device_list.lock);
	list_del_init(&entry->list);
	spin_unlock(&ib_device_list.lock);

   /* this needs more work */

	kfree(entry);
}

/* Handle a completion queue notication that is sent when an RDMA
command completes. While we are here, empty the queue of any other
completions that we can handle to avoid the context switch */
static void cq_comp_handler(struct ib_cq *cq, struct ib_wc *wc)
{
   int ret;
	struct ib_wc nextc;

   do {
	   struct ib_cqe *cqe = wc->wr_cqe;
      struct rpf_link *link = cq->cq_context;
	   if (wc->status == IB_WC_WR_FLUSH_ERR)
	      continue;

		switch(wc->opcode) {
      case IB_WC_RDMA_READ:
		   if (wc->status) {
				printk("RPF: cq completion failed with "
						 "wr_id %Lx status %d opcode %d vender_err %x\n",
					wc->wr_id, wc->status, wc->opcode, wc->vendor_err);
			}
	      complete(&link->cq_done);
         kfree(cqe);
         break;

      case IB_WC_RECV:
	      complete(&link->cq_done);
         break;

      default:
			printk("unexpected completion for opcode %d\n", wc->opcode);
		}
	} while (((ret = ib_poll_cq(cq, 1, &nextc)) == 1) && (wc = &nextc));

	if (ret)
		printk("RPF: poll error %d\n", ret);
}

/* Handle an event from the connection manager */
int cm_event_handler(struct rdma_cm_id *cm_id,
			      struct rdma_cm_event *event)
{
   int ret = 0;
   rpf_link *link = cm_id->context;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_ERROR:
      printk("RPF: address resolution error\n");
      break;

	case RDMA_CM_EVENT_ADDR_RESOLVED:
      link->state = LINK_STATE_ADDR_RESOLVED;
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
      link->state = LINK_STATE_ROUTE_RESOLVED;
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
      link->state = LINK_STATE_CONNECTED;
		break;

	case RDMA_CM_EVENT_REJECTED:
      printk("RPF: connection rejected\n");
      break;

	case RDMA_CM_EVENT_DISCONNECTED:
      printk("RPF: discconnected\n");
      break;

   default:
      printk("RPF: got unhandled CM event %i\n", event->event);
      break;
   }
	complete(&link->cm_done);
	return ret;
}

static inline int
rdma_post_recv(rpf_link *link,
         void (*compl_fn)(struct ib_cq *cq, struct ib_wc *wc),
         void *addr, size_t length, struct ib_pd *pd)
{
	struct ib_recv_wr wr, *bad_wr;
	struct ib_sge sge;
	struct ib_cqe *cqe; /* completion queue entry */

	sge.addr = (uint64_t) addr;
	sge.length = (uint32_t) length;
	sge.lkey = pd->local_dma_lkey;

	cqe = kzalloc(sizeof(struct ib_cqe), GFP_KERNEL);
	cqe->done = compl_fn;

	wr.next = NULL;
	wr.wr_cqe = cqe;
	wr.sg_list = &sge;
	wr.num_sge = 1;
   return ib_post_recv(link->cm_id->qp, &wr, &bad_wr);
}

int rpf_setup_link(struct rpf_link *link)
{
	struct ib_qp_init_attr qp_attr;
   int ret;

   printk("RPF: setup_link\n");
   if (link->state != LINK_STATE_ROUTE_RESOLVED) {
      printk("Link route not resolved\n");
      return -1;
   }

   /* allocate Protection Domain */
   link->pd = ib_alloc_pd(link->cm_id->device, 0);
	if (IS_ERR(link->pd)) {
		ret = PTR_ERR(link->pd);
		printk("RPF: ib_alloc_pd failed %i\n", ret);
      goto err_pd;
	}

   /* create completion queue */
   link->cq = ib_alloc_cq(link->cm_id->device, link, 3, 0, IB_POLL_SOFTIRQ);
	if (IS_ERR(link->cq)) {
		ret = PTR_ERR(link->cq);
		printk("RPF: ib_create_cq failed %i\n", ret);
      goto err_cq;
	}

   /* create the queue pair */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.cap.max_send_wr = 2;
	qp_attr.cap.max_recv_wr = 2;
	qp_attr.cap.max_recv_sge = 1;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.qp_type = IB_QPT_RC;
	qp_attr.send_cq = link->cq;
	qp_attr.recv_cq = link->cq;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

	ret = rdma_create_qp(link->cm_id, link->pd, &qp_attr);
   if (ret != 0) {
      printk("RPF: error creating qp\n");
      goto err_qp;
   }

   link->state = LINK_STATE_READY;

   printk("RPF: init ok!\n");
   return 0;

err_qp:
	printk("RPF: destroy_cq\n");
   ib_free_cq(link->cq);
   link->cq = NULL;

err_cq:
   printk("ib_dealloc_pd\n");
	ib_dealloc_pd(link->pd);
   link->pd = NULL;

err_pd:
   link->state = LINK_STATE_ROUTE_RESOLVED;
   return ret;
}

static int rpf_run(struct rpf_link *link, unsigned int srv_ip, unsigned short srv_port)
{
   struct sockaddr_in srv;
   struct mr_context srv_ctx;
	int ret;
   unsigned int pagesize;
   struct rdma_conn_param conn_param;

	/* Create the RDMA CM ID  */
   printk("rdma_create_id\n");
	link->cm_id = rdma_create_id(&init_net, cm_event_handler, link,
				     RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(link->cm_id)) {
      printk("RPF: error creating cm_id\n");
		goto err_ep;
   }

	memset(&srv, 0, sizeof(struct sockaddr));
	srv.sin_family = AF_INET;
	srv.sin_addr.s_addr = srv_ip;
	srv.sin_port = htons(srv_port);
   printk("Resolving server address %pI4\n", &srv.sin_addr.s_addr);
	ret = rdma_resolve_addr(link->cm_id, NULL,
				(struct sockaddr *)&srv,
				RDMA_RESOLVE_TIMEOUT);
	if (ret) {
      printk("RPF: can't resolve server address\n");
		goto err_resolve;
   }

	ret = wait_for_completion_interruptible(&link->cm_done);
	if (ret || (link->state != LINK_STATE_ADDR_RESOLVED)) {
      printk("RPF: server address not resolved\n");
		goto err_resolve;
   }

	/* Resolve the route to the server */
	ret = rdma_resolve_route(link->cm_id, RDMA_RESOLVE_TIMEOUT);
	if (ret) {
      printk("RPF: can't resolve server route %i\n", ret);
		goto err_resolve;
   }

	ret = wait_for_completion_interruptible(&link->cm_done);
	if (ret || (link->state != LINK_STATE_ROUTE_RESOLVED)) {
      printk("RPF: server route not resolved\n");
		goto err_resolve;
   }

   rpf_setup_link(link);

   pagesize = 65536; //sysconf(_SC_PAGE_SIZE); get pagesize

	link->recv_msg = ib_dma_alloc_coherent(link->cm_id->device,
						RDMA_XCHNG_BUF_SIZE,
					   &link->recv_msg_dma, GFP_KERNEL);
	if (!link->recv_msg) {
		ret = -ENOMEM;
		printk("ib_dma_alloc_coherent send failed\n");
		goto err_reg_xchng;
	}

   /* get memory region details from server */
	ret = rdma_post_recv(link, cq_comp_handler, (void*)link->recv_msg_dma,
      RDMA_XCHNG_BUF_SIZE, link->pd);
	if (ret) {
		printk("RPF: error %i posting recv\n", ret);
		goto err_connect;
	}

   printk("Connecting\n");
	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.private_data = NULL;
	conn_param.private_data_len = 0;
	conn_param.responder_resources = RDMA_MAX_OUTSTANDING_READS;
	conn_param.initiator_depth = 1;
	ret = rdma_connect(link->cm_id, &conn_param);
	if (ret) {
      printk("Error %i trying to connect\n", ret);
		goto err_connect;
   }
	ret = wait_for_completion_interruptible(&link->cm_done);
	if (ret || (link->state != LINK_STATE_CONNECTED)) {
      printk("Unable to connect\n");
		goto err_connect;
   }

   printk("waiting for server's MR info\n");
	ret = wait_for_completion_interruptible(&link->cq_done);
	if (ret)
		printk("can't get MR info");

   memcpy(&srv_ctx, link->recv_msg, sizeof(struct mr_context));
   printk("Got MR info: addr=%p rkey=0x%x\n", srv_ctx.addr, srv_ctx.rkey);
   link->rkey = srv_ctx.rkey;
   ib_dma_free_coherent(link->cm_id->device, 16, link->recv_msg, link->recv_msg_dma);
   return 0;

err_connect:
   ib_dma_free_coherent(link->cm_id->device, 16, link->recv_msg, link->recv_msg_dma);
err_reg_xchng:
err_ep:
err_resolve:
   return -1;
}

static int unregister_pid(struct rpf_link *link)
{
	struct userfaultfd_wake_range range;

	if (link->uf_ctx) {
      // wake up uffd with a bad range so it will quit
		range.start = 0;
		range.len = 1;
	   spin_lock(&link->uf_ctx->fault_pending_wqh.lock);
		__wake_up_locked_key(&link->uf_ctx->fault_wqh, TASK_NORMAL, &range);
	   spin_unlock(&link->uf_ctx->fault_pending_wqh.lock);

		userfaultfd_ctx_release(link->uf_ctx);
		link->uf_ctx = NULL;
	}

	return 0;
}

void rpf_cleanup_link(struct rpf_link *link)
{
   printk("RPF: cleanup_resources\n");

	/* if there is an open uffd context, close it */
	unregister_pid(link);

   if (link->recv_msg_dma) {
      ib_dma_free_coherent(link->cm_id->device, RDMA_XCHNG_BUF_SIZE,
         link->recv_msg, link->recv_msg_dma);
      link->recv_msg_dma = 0;
   }

   if (link->state == LINK_STATE_CONNECTED) {
      rdma_disconnect(link->cm_id);
      link->state = LINK_STATE_INIT;
   }

   if (link->cm_id) {
      rdma_destroy_qp(link->cm_id);
      rdma_destroy_id(link->cm_id);
      link->cm_id = NULL;
   }

   if (link->cq) {
      ib_free_cq(link->cq);
      link->cq = 0;
   }

   if (link->pd) {
      ib_dealloc_pd(link->pd);
      link->pd = 0;
   }

   link->state = LINK_STATE_UNINIT;
}

int read_remote_page(rpf_link *link, u64 remote_addr, dma_addr_t dest, unsigned int pagesize)
{
   int ret;
	struct ib_sge sge;
   struct ib_cqe *wr_cqe;
	struct ib_rdma_wr	rdma_wr;
   struct ib_send_wr *bad_swr;

   
	wr_cqe = kzalloc(sizeof(struct ib_cqe), GFP_KERNEL);
	wr_cqe->done = cq_comp_handler;

	// fill the page from the remote server
	sge.addr = dest;
	sge.length = pagesize;
	sge.lkey = link->pd->local_dma_lkey;

   rdma_wr.wr.next = NULL;
   rdma_wr.wr.wr_cqe = wr_cqe;
	rdma_wr.wr.sg_list = &sge;
	rdma_wr.wr.num_sge = 1;
	rdma_wr.wr.opcode = IB_WR_RDMA_READ;
   rdma_wr.wr.send_flags = IB_SEND_SIGNALED;
   rdma_wr.remote_addr = remote_addr;
   rdma_wr.rkey = link->rkey;

   ib_req_notify_cq(link->cq, IB_CQ_NEXT_COMP);

   //printk("Requesting RDMA READ from 0x%llx with key 0x%x len %u buffer 0x%llx\n", rdma_wr.remote_addr, rdma_wr.rkey, sge.length, sge.addr);
   ret = ib_post_send(link->cm_id->qp, &rdma_wr.wr, &bad_swr);
	if (ret) {
		printk("failed to send page request: %d\n", ret);
		return -1;
	}

	ret = wait_for_completion_interruptible(&link->cq_done);
	if (ret) {
      printk("RPF: couldn't get remote page\n");
      return -1;
   }

   return 0;
}

/************** UFFD *********************/

/* the page fault handler thread main function */
static int uffd_handler(void *data)
{
	int ret;
	struct page *newpage;
	struct uffd_msg msg;
	struct userfaultfd_wake_range range;
   struct rpf_link *link = data;
	void *page_kaddr;
	unsigned long dst_addr=0;
   dma_addr_t page_dma;
   unsigned int pagesize = 65536;
   int running=1;
   unsigned long long before, after;

	printk("RPF: handler thread\n");

   if (!link) {
      printk("RPF: null link in handler thread\n");
      return -1; /* should probably kill the app here */
   }

   while (running) {
      if (kthread_should_stop()) {
         running = 0;
         printk("RPF: thread should stop\n");
         goto wake;
      }

      // wait for a page fault
      ret = userfaultfd_ctx_read(link->uf_ctx, 0, &msg);
      if (ret < 0) {
         printk("RPF: ctx read failed\n");
         continue;
      }

		dst_addr = msg.arg.pagefault.address;
		if (msg.event != UFFD_EVENT_PAGEFAULT) {
			printk("RPF: not a pagefault event\n");
			continue;
		}

		// got a page fault

/*
		if (dst_addr < link->uf_ctx->reg.range.start || dst_addr > link->uf_ctx->reg.range.end) {
			printk("RPF: pagefault out of range (%lu)\n", dst_addr);
			continue;
		}
*/

         //blank_page = list_pop_head(blank_page_list);
		// set up a blank page and map it into the user context
      MFSPR(before);
		newpage = alloc_pages(GFP_HIGHUSER_MOVABLE, 0);
      MFSPR(after);

		printk("RPF: got page struct in %llu\n", after - before);
		if (!newpage) {
			printk("RPF: can't get page struct for address 0x%lx\n", dst_addr);
			continue;
		}

		page_kaddr = kmap_atomic(newpage);
		if (!page_kaddr) {
			printk("RPF: couldn't allocate empy page\n");
			continue;
		}

      /* map the page for DMA */
	   page_dma = ib_dma_map_single(link->cm_id->device,
				    page_kaddr, pagesize,
				    DMA_FROM_DEVICE);

      // read the remote page to the correct location
	   if (!ib_dma_mapping_error(link->cm_id->device, page_dma))
         read_remote_page(link, dst_addr, page_dma, pagesize);

      // unmap the DMA address
	   ib_dma_unmap_single(link->cm_id->device,
				    page_dma, pagesize,
				    DMA_FROM_DEVICE);

      // unmap the kernel virtual address
		kunmap_atomic(page_kaddr);

		// map it to userspace at the requested virtual address
		ret = vm_insert_anonymous_page(link->uf_ctx->mm, dst_addr, newpage);
		if (ret) {
			printk("RPF: error inserting page %i\n", ret);
			put_page(newpage);
		}

wake:
		// we're done - wake up the waiting process
		range.start = dst_addr;
		range.len = pagesize;
		userfaultfd_ctx_wake(link->uf_ctx, &range);
   }

   printk("RPF: handler thread exiting\n");
   return 0;
}

//static struct userfaultfd_ctx *register_pid(unsigned int pid, __u64 start, __u64 end)
static struct userfaultfd_ctx *register_pid(unsigned int pid, struct rpf_link *link)
{
	int ret;
   struct mm_struct *mm;
   struct task_struct *task;
   struct userfaultfd_ctx *ctx;
   struct uffdio_register reg = {
      .mode = UFFDIO_REGISTER_MODE_MISSING,
      .range = {
         .start = (uintptr_t)0x001234000000,
         .len = (0x10000000),
         }
   };

   /* the process (as performed in userspace) is as follows:
   1. call the syscall with O_NONBLOCK
   2. negotiate a protocol version with ioctl(UFFDIO_API)
   3. register a memory area with ioctl(UFFDIO_REGISTER)
   4. start a handler thread

	In kernel space, we obviously don't have a syscall or ioctl so things are a
	bit different. We also don't need to negotiate the API version, since we are
	a module of the kernel and therefore we know what version we have.

	What we don't know is the mm (page tables) of the process, since it is no
	longer possible to assume the 'current' process is the one who's faults we
	want to handle!
	*/

	task = pid_task(find_vpid(pid), PIDTYPE_PID);

	if (task == NULL)
	{
		printk("RPF: Not able to find the task for pid %u\n", rpf.active_pid);
		return NULL; // pid has no task_struct
	}

	mm = task->mm ? task->mm : task->active_mm;

	if (mm == NULL) {
		printk("RPF: Not able to find valid mm for pid %u!\n", rpf.active_pid);
		return NULL; // this shouldn't happen, but just in case
	}

	/* create the context */
	ctx = userfaultfd_ctx_create(O_NONBLOCK, mm);
	if (!ctx) {
		printk("RPF: uffd_ctx_create failed\n");
		return NULL;
	}

	/* we don't need step 2, since we are in the kernel - go to step 3 */
	ret = userfaultfd_ctx_register(ctx, &reg);
	if (ret) {
		printk("RPF: uffd_ctx_register failed %i\n", ret);
		goto error;
	}

	/* and step 4 */
   rpf.handler = kthread_run(uffd_handler, link, "rpf_handler");
	if (!rpf.handler) {
		printk("RPF: error creating uffd thread\n");
		goto error;
	}

   return ctx;

error:
	if (ctx) {
		userfaultfd_ctx_release(ctx);
	}
	return NULL;
}

static int __init init_sysfs(void)
{
	rpf.sysfsroot = kobject_create_and_add("rpf", NULL);
	if (!rpf.sysfsroot)
		return 1;

	sysfs_create_group(rpf.sysfsroot, &rpf_attr_group);

	return 0;
}

static void __exit cleanup_sysfs(void)
{
	kobject_del(rpf.sysfsroot);
}

/* sysfs accessor functions */
ssize_t show_readme(struct kobject *kobj, struct kobj_attribute *attr, char *buff)
{
	strcpy(buff, help_text);
	return strlen(help_text);
}

ssize_t show_pid(struct kobject *kobj, struct kobj_attribute *attr, char *buff)
{
	int chars = sprintf(buff, "%u\n", rpf.active_pid);
	return chars;
}

ssize_t store_pid(struct kobject *kobj, struct kobj_attribute *attr, const char *buff, size_t size)
{
   struct rpf_link *link;
	unsigned int pid;

	if (sscanf(buff, "%u", &pid) != 1)
		return 0;

   if (!pid)
      return size;

	link = kzalloc(sizeof(struct rpf_link), GFP_KERNEL);
	if (!link) {
      printk("RPF: Unable to allocate memory on_device_add\n");
		return size;
   }

   // when a pid is added, its memory should be registered immediately with userfaultfd
   link->uf_ctx = register_pid(pid, link);
   if (!link->uf_ctx) {
      printk("RPF: Error registering pid\n");
      return size;
   }

	init_completion(&link->cm_done);
	init_completion(&link->cq_done);

   // now set up RDMA
   rpf_run(link, rpf.rhost_ip, rpf.rhost_port);

   rpf.active_pid = pid;

   return size;
}

ssize_t show_server(struct kobject *kobj, struct kobj_attribute *attr, char *buff)
{
	sprintf(buff, "%pI4\n", &rpf.rhost_ip);
	return strlen(buff);
}

ssize_t store_server(struct kobject *kobj, struct kobj_attribute *attr, const char *buff, size_t size)
{
	in4_pton(buff, -1, (u8*)&rpf.rhost_ip, -1, NULL);

   return strlen(buff);
}

ssize_t show_port(struct kobject *kobj, struct kobj_attribute *attr, char *buff)
{
   sprintf(buff, "%u\n", rpf.rhost_port);
	return strlen(buff);
}

ssize_t store_port(struct kobject *kobj, struct kobj_attribute *attr, const char *buff, size_t size)
{
   unsigned long port;
   if (kstrtoul(buff, 0, &port))
      printk("Error converting port number to int\n");

   rpf.rhost_port = port & 0xFFFF;

   return strlen(buff);
}

static int __init rpf_init_module(void)
{
	rpf.active_pid = 0;
   rpf.link.state = LINK_STATE_UNINIT;

	// get notifications about what RDMA devices are available
	ib_register_client(&rpf_ib_client);

   if (init_sysfs()) {
      printk("RPF: error initializing sysfs\n");
      return -1;
   }

   return 0;
}

static void __exit rpf_cleanup_module(void)
{
   printk("RPF: exit\n");

	ib_unregister_client(&rpf_ib_client);

   rpf_cleanup_link(&rpf.link);

	cleanup_sysfs();
}

module_init(rpf_init_module);
module_exit(rpf_cleanup_module);

MODULE_AUTHOR("joeln@il.ibm.com");
MODULE_DESCRIPTION("Remote page fault handler over RoCE");
MODULE_LICENSE("GPL");
