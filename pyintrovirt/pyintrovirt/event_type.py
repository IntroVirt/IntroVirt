"""Re-export IntroVirt event types as a Python Enum"""
from enum import Enum

import introvirt


class EventType(Enum):
    """IntroVirt VMI EventType enum."""
    EVENT_FAST_SYSCALL = introvirt.EventType_EVENT_FAST_SYSCALL
    EVENT_FAST_SYSCALL_RET = introvirt.EventType_EVENT_FAST_SYSCALL_RET
    EVENT_SW_INT = introvirt.EventType_EVENT_SW_INT
    EVENT_SW_IRET = introvirt.EventType_EVENT_SW_IRET
    EVENT_CR_READ = introvirt.EventType_EVENT_CR_READ
    EVENT_CR_WRITE = introvirt.EventType_EVENT_CR_WRITE
    EVENT_MSR_READ = introvirt.EventType_EVENT_MSR_READ
    EVENT_MSR_WRITE = introvirt.EventType_EVENT_MSR_WRITE
    EVENT_EXCEPTION = introvirt.EventType_EVENT_EXCEPTION
    EVENT_MEM_ACCESS = introvirt.EventType_EVENT_MEM_ACCESS
    EVENT_SINGLE_STEP = introvirt.EventType_EVENT_SINGLE_STEP
    EVENT_HYPERCALL = introvirt.EventType_EVENT_HYPERCALL
    EVENT_REBOOT = introvirt.EventType_EVENT_REBOOT
    EVENT_SHUTDOWN = introvirt.EventType_EVENT_SHUTDOWN
    EVENT_MAX = introvirt.EventType_EVENT_MAX
    EVENT_UNKNOWN = introvirt.EventType_EVENT_UNKNOWN