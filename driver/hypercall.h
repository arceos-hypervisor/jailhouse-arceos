#ifndef _JAILHOUSE_HYPERCALL_H
#define _JAILHOUSE_HYPERCALL_H

#define JAILHOUSE_HC_DISABLE			0

/*
 * As this is never called on a CPU without VM extensions,
 * we assume that where VMCALL isn't available, VMMCALL is.
 */
#define JAILHOUSE_CALL_CODE	\
	"cmpb $0x01, %[use_vmcall]\n\t"\
	"jne 1f\n\t"\
	"vmcall\n\t"\
	"jmp 2f\n\t"\
	"1: vmmcall\n\t"\
	"2:"

#define JAILHOUSE_CALL_RESULT	"=a" (result)
#define JAILHOUSE_USE_VMCALL	[use_vmcall] "m" (jailhouse_use_vmcall)
#define JAILHOUSE_CALL_NUM	"a" (num)
#define JAILHOUSE_CALL_ARG1	"D" (arg1)
#define JAILHOUSE_CALL_ARG2	"S" (arg2)

/**
 * This variable selects the x86 hypercall instruction to be used by
 * jailhouse_call(), jailhouse_call_arg1(), and jailhouse_call_arg2().
 * A caller should define and initialize the variable before calling
 * any of these functions.
 *
 * @li @c false Use AMD's VMMCALL.
 * @li @c true Use Intel's VMCALL.
 */
extern bool jailhouse_use_vmcall;

/**
 * Invoke a hypervisor without additional arguments.
 * @param num		Hypercall number.
 *
 * @return Result of the hypercall, semantic depends on the invoked service.
 */
static inline __u32 jailhouse_call(__u32 num)
{
	__u32 result;

	asm volatile(JAILHOUSE_CALL_CODE
		: JAILHOUSE_CALL_RESULT
		: JAILHOUSE_USE_VMCALL, JAILHOUSE_CALL_NUM
		: "memory");
	return result;
}

/**
 * Invoke a hypervisor with one argument.
 * @param num		Hypercall number.
 * @param arg1		First argument.
 *
 * @return Result of the hypercall, semantic depends on the invoked service.
 */
static inline __u32 jailhouse_call_arg1(__u32 num, unsigned long arg1)
{
	__u32 result;

	asm volatile(JAILHOUSE_CALL_CODE
		: JAILHOUSE_CALL_RESULT
		: JAILHOUSE_USE_VMCALL,
		  JAILHOUSE_CALL_NUM, JAILHOUSE_CALL_ARG1
		: "memory");
	return result;
}

/**
 * Invoke a hypervisor with two arguments.
 * @param num		Hypercall number.
 * @param arg1		First argument.
 * @param arg2		Second argument.
 *
 * @return Result of the hypercall, semantic depends on the invoked service.
 */
static inline __u32 jailhouse_call_arg2(__u32 num, unsigned long arg1,
					unsigned long arg2)
{
	__u32 result;

	asm volatile(JAILHOUSE_CALL_CODE
		: JAILHOUSE_CALL_RESULT
		: JAILHOUSE_USE_VMCALL,
		  JAILHOUSE_CALL_NUM, JAILHOUSE_CALL_ARG1, JAILHOUSE_CALL_ARG2
		: "memory");
	return result;
}

#endif /* !_JAILHOUSE_HYPERCALL_H */
