# bg_jobs.py
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading
from typing import Any, Callable, Optional, Tuple

import panel as pn

# Small, safe background job runner for Panel/Bokeh:
# - runs heavy work in a thread pool
# - marshals UI updates back to main event loop via pn.state.add_next_tick_callback
# - returns monotonically increasing job_id for anti-race on the caller side

_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="mybot-bg")
_lock = threading.Lock()
_job_seq = 0


def submit(
    job_fn: Callable[[], Any],
    on_done: Callable[[int, Optional[Any], Optional[BaseException]], None],
) -> int:
    """
    Submit a background job.

    job_fn: heavy work (NO UI touches inside)
    on_done: called on UI thread via next_tick as: on_done(job_id, result, error)
    """
    global _job_seq
    with _lock:
        _job_seq += 1
        job_id = int(_job_seq)

    fut = _executor.submit(job_fn)

    def _done_callback(f) -> None:
        try:
            res = f.result()
            err: Optional[BaseException] = None
        except BaseException as e:
            res = None
            err = e

        # Marshal back to UI loop.
        # Panel 1.x: use pn.state.curdoc.add_next_tick_callback
        doc = getattr(pn.state, "curdoc", None)
        cb = lambda: on_done(job_id, res, err)
        if doc is not None and hasattr(doc, "add_next_tick_callback"):
            doc.add_next_tick_callback(cb)
        else:
            # Fallback (e.g. running outside a server)
            cb()

    fut.add_done_callback(_done_callback)
    return job_id

