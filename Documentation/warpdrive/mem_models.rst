Memory Model
============

We consider the system is organized as follow: ::

  +------------------+    +-----------------+  +--------------+
  | CPU Cluster      |    | Accelerator     +--| Acc priv mem |
  +--------+---------+    +--------+--------+  +--------------+
           |                       |
  ---------+-----------------------+--------- bus
           |                       |
  +--------+---------+    +--------+--------+
  | comm mem for cpu |    | comm mem in acc |
  +------------------+    +-----------------+


We are going to support the following memory using models:

1. The application have the memory to be handled by the accelerator
        The model will be: ::

                p = the_mem_owned_by_app();
                wd_mem_share(wd_queue, p);
                wd_operation(wd_queue, p); //wd_send/recv_...()
                wd_mem_unshare(wd_queue, p);

        The shortage is that the share and unshare is a syscall and the smmu operation take time.
        Or it can be done by a *WD_CAPA_SHARE_ALL*. So the *wd_mem_share* and *wd_mem_unshare* are 
        not necessary.

2. Legacy model

        The model will be: ::

                p = the_mem_owned_by_app();
                wd_operation(wd_queue, p);

        The shortage is that the wd_operation is a or some syscalls. It will
        get the hardware address for further operation.

3. Use the framework memory

        The model is: ::

                p = wd_alloc(wd_queue, size);
                app_fill_data(p);
                wd_operation(wd_queue, p);
                wd_free(p);

        The shortage is that the application may need to change to adopt it.
        The model is good for the hardware with "near" memory to the Accelerator.

4. The accelerator accept only private memory

        The model is the same as the previous models. The copy (to the Acc priv
        mem) operation is taken as one of the wd_operation().
