"""Event handling helpers and classes."""
import traceback
from typing import Protocol

import introvirt


class EventCallback(Protocol):
    """The event callback function signature."""
    def __call__(self, event: introvirt.Event) -> None: ...


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

        # Get the event to send (OS-specific or generic)
        send_event = os_event if os_event else event

        # Send it to the global callback if it's set
        if self.global_event_callback:
            self.global_event_callback(send_event)

        # Find any specific event handling callback to send it to next.
        callback = self.event_callbacks.get(introvirt.EventType(send_event.type()))
        if callback:
            callback(send_event)
