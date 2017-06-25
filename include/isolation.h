#ifndef ISOLATION_H
#define ISOLATION_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize/destroy libisolation.
 * Run once for each in one program.
 */
int isl_init(void);
int isl_destroy(void);

typedef int isl_handle_t;

/*
 * Launches a new virtual machine and loads the dynamic library specified by _filename_ into the VM.
 *
 * TODO: add a parameter to specify which dependent libraries are loaded into the VM togather.
 */
isl_handle_t isl_open(const char *filename);
int isl_close(isl_handle_t handle);

typedef int isl_sym_t;

/*
 * Gets a "function poiner" that points to the function named _symbol_ in the VM.
 * The "pointer" also contains information about the number of parameters and their types.
 *
 * NB: isl_sym currently only supports functions of type "void *f(void *)".
 */
isl_sym_t isl_sym(int handle, const char *symbol);
void isl_free(int handle, isl_sym_t f);

typedef enum {
  ISL_SUCCESS = 0,
  ISL_EINVAL = -1,
  ISL_EFAULT = -2,
  ISL_ESYSCALL = -3,
  ISL_EEXTCALL = -4,
  ISL_ERROR = - 5,
} isl_return_t;

/*
 * Calls a function _f_ in the VM with arguments _args_.
 * Sensitive events occured in the VM are trapped and notified to the host.
 *
 * NB: Currently isl_call only supports one argument; args must be always an array of one pointer to some pointer.
 * TODO: add a parameter to specify which events are trapped.
 */
isl_return_t isl_call(int handle, isl_sym_t f, void *args[]);
isl_return_t isl_resume(int handle);

/*
 * Allow/disallow the program in the VM to read/write/execute a memory region specified by _addr_ and _length_.
 * Remember that the guest program shares the same address space with the host program.
 */
int isl_map(int handle, void *addr, size_t length, int prot);
int isl_unmap(int handle, void *addr, size_t length);

#ifdef __cplusplus
}
#endif

#endif
