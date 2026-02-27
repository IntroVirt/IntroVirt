"""Event handling helpers and classes."""
import traceback
from typing import Protocol, Union

import introvirt


class EventCallback(Protocol):
    """The event callback function signature."""
    def __call__(self, event: "Event") -> None: ...


class Event:
    """A more helpful wrapper around introvirt.Event that exposes more functionality from one object."""

    def __init__(self, iv_event: introvirt.Event):
        self._iv_event = iv_event
        self._syscall: introvirt.SystemCallEvent = None
        self._handler: introvirt.SystemCall = None
        self._vcpu: introvirt.Vcpu = self._iv_event.vcpu()
        self._task: introvirt.EventTaskInformation = self._iv_event.task()

        if introvirt.EventType(self._iv_event.type()) in (introvirt.EventType.EVENT_FAST_SYSCALL, introvirt.EventType.EVENT_FAST_SYSCALL_RET):
            self._syscall = iv_event.syscall()
            self._handler = self._syscall.handler()

    def __str__(self) -> str:
        supp = ""
        if self.supported is False:
            supp = " - unsupported"

        if self.has_result():
            return f"Vcpu {self.vcpu.id()}: [{self.pid}:{self.tid}] {self.process_name}\n\t{self.syscall_name} - {self.get_result_str()}{supp}\n"
        else:
            return f"Vcpu {self.vcpu.id()}: [{self.pid}:{self.tid}] {self.process_name}\n\t{self.syscall_name}{supp}\n"

    def is_syscall(self) -> bool:
        """Is it a system call event."""
        return self._syscall is not None

    @property
    def supported(self) -> Union[None, bool]:
        """Checks supported. Only valid for system calls with a handler."""
        if self.is_syscall() and self._handler:
            return self._handler.supported()
        return None

    @property
    def pid(self) -> int:
        """Get the process ID for the task associated with the event."""
        return self._task.pid()

    @property
    def tid(self) -> int:
        """Get the thread ID for the task associated with the event."""
        return self._task.tid()

    @property
    def vcpu(self) -> introvirt.Vcpu:
        """Get access to the VCPU object."""
        return self._vcpu

    @property
    def process_name(self) -> str:
        """Get the task info process name."""
        return self._task.process_name()

    @property
    def syscall_name(self) -> Union[None, str]:
        """Get the system call name if it's a system call."""
        if not self.is_syscall():
            return None
        return self._syscall.name()

    def event_type(self) -> introvirt.EventType:
        """Wrap in an introvirt.EventType object."""
        return introvirt.EventType(self._iv_event.type())

    def will_return(self) -> Union[None, bool]:
        """This is valid for system calls. Everything else will always return False."""
        if not self.is_syscall():
            return None  # Not a system call
        if not self._handler:
            return None  # No supported handler
        if self.event_type() != introvirt.EventType.EVENT_FAST_SYSCALL:
            return None  # Not a system call call
        return self._handler.will_return()

    def hook_return(self, enabled: bool):
        """Set whether or not we'll hook the return. Only valid on system calls."""
        if not self.is_syscall():
            return  # Not a system call
        if self.event_type() != introvirt.EventType.EVENT_FAST_SYSCALL:
            return  # Not a system call call
        self._syscall.hook_return(enabled)

    def has_result(self) -> bool:
        return self.is_syscall() and self.event_type() == introvirt.EventType.EVENT_FAST_SYSCALL_RET and isinstance(self._iv_event, introvirt.WindowsEvent)

    def get_result(self) -> Union[None, int]:
        """Get the result value if there is one. Only valid for system calls right now."""
        if not self.is_syscall():
            return None  # Not a system call
        if self.event_type() != introvirt.EventType.EVENT_FAST_SYSCALL_RET:
            return None  # Not a system call return
        if not isinstance(self._iv_event, introvirt.WindowsEvent):
            return None  # Not supported

        ok, value = introvirt.get_windows_syscall_result_value(self._iv_event)
        if not ok:
            return None  # Not ok

        return value

    def get_result_str(self) -> Union[None, str]:
        """Get the result value if there is one as a string. Only valid for system calls right now."""
        value = self.get_result()
        if value is not None and isinstance(self._iv_event, introvirt.WindowsEvent):
            return introvirt.ntstatus_to_string(value)
        return None


class CallbackEventHandler(introvirt.EventCallback):
    """Event callback handler."""

    def __init__(self):
        super().__init__()  # required so SWIG director wrapper is created for poll()
        self.event_callbacks = {}
        self.global_event_callback = None

    def set_global_event_callback(self, callback: EventCallback):
        """Set a callback to be called with every event type."""
        self.global_event_callback = callback

    def register_event_callback(self, event_type: introvirt.EventType, callback: EventCallback):
        """Set a callback to be called for a specific event type."""
        self.event_callbacks[event_type] = callback

    def process_event(self, event: introvirt.Event):
        """Callback from the introvirt.EventCallback"""
        try:
            self._process_event(event)
        except Exception as exc:
            # TODO: Logging
            print(f"Unhandled exception processing event: {exc}")
            traceback.print_exc()

    def _process_event(self, event: introvirt.Event):
        """Called internally for each event received."""
        if not self.event_callbacks and not self.global_event_callback:
            return  # no callbacks to call

        os_event = None
        match introvirt.OS(event.os_type()):
            case introvirt.OS.Windows:
                os_event = introvirt.WindowsEvent_from_event(event)
            case introvirt.OS.Linux:
                raise NotImplementedError("Linux guest introspection is not implemented yet")

        # Get the event to use (OS-specific or generic)
        iv_event = os_event if os_event else event
        send_event = Event(iv_event)

        # Send it to the global callback if it's set
        if self.global_event_callback:
            self.global_event_callback(send_event)

        # Find any specific event handling callback to send it to next.
        callback = self.event_callbacks.get(introvirt.EventType(send_event.event_type()))
        if callback:
            callback(send_event)
