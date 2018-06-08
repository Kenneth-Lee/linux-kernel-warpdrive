When to use accelerator
=======================

There is cost to deliver a task to the accelerator. So an external accelerator
is suitable for heavy task such as RSA.  Or, it can be used when the
application can combine several sub-tasks in one request.

For the CPU orient algorithm, the use mode is synchronized. The caller will wait
until the task is finished. But the hardware accelerator prefer a
asynchronized, pipeline like model. Therefore more queues are prefer to the
accelerator, so it can serve more application without the need for the
application change its use mode.
