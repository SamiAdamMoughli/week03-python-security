import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor

def run_demo1():
    def worker(thread_name, delay=0.3):
        time.sleep(delay)
        print(f"I'm {thread_name}")

    start = time.perf_counter()
    for i in range(3):
        worker(f"Thread-{i}")
    seq_time = time.perf_counter() - start

    start = time.perf_counter()
    threads = [threading.Thread(target=worker, args=(f"Thread-{i}",)) for i in range (3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    thr_time = time.perf_counter() - start

    return seq_time, thr_time

def run_demo2():
    def make_counter():
        counter = 0
        def increment():
            nonlocal counter
            for _ in range(50):
                current = counter
                time.sleep(0.00001)
                counter = current + 1
        return increment, lambda: counter

    fn, get = make_counter()
    start = time.perf_counter()
    for _ in range(10):
        fn()
    seq_time = time.perf_counter() - start
    print(f"sequential: {get()} (expected 500)")

    fn, get = make_counter()
    start = time.perf_counter()
    threads = [threading.Thread(target=fn) for _ in range(10)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()
    thr_time = time.perf_counter() - start
    print(f"threaded: {get()} (expected 500)")

    return seq_time, thr_time

def run_demo3():
    lock = threading.Lock()

    def make_counter() -> int:
        counter = 0
        def increment():
            nonlocal counter
            for _ in range(50):
                with lock:
                    current = counter
                    time.sleep(0)
                    counter = current + 1
        return increment, lambda: counter

    fn, get = make_counter()
    start = time.perf_counter()
    for _ in range(10):
        fn()
    seq_time = time.perf_counter() - start
    print(f"sequential: {get()} (expected 500)")

    fn, get = make_counter()
    start = time.perf_counter()
    threads = [threading.Thread(target=fn) for _ in range(10)]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    thr_time = time.perf_counter() - start
    print(f"threaded: {get()} (expected 500)")

    return seq_time, thr_time

def run_demo4():
    def io_task(task_id):
        time.sleep(random.uniform(0.05, 0.015))
        return f"task-{task_id} done"

    start = time.perf_counter()
    for i in range(20):
        io_task(i)
    seq_time = time.perf_counter() - start

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=5) as ex:
        results = list(ex.map(io_task, range(20)))
    thr_time = time.perf_counter() - start
    print(f"{len(results)} tasks done")

    return seq_time, thr_time

def run_demo5():
    def run(threaded):
        stop_event = threading.Event()
        ticks = []

        def worker():
            while not stop_event.is_set():
                ticks.append(1)
                time.sleep(0.1)

        start = time.perf_counter()
        if threaded:
            t = threading.Thread(target=worker)
            t.start()
            time.sleep(0.45)
            stop_event.set()
            t.join()

        else:
            end = time.perf_counter() + 0.45
            while time.perf_counter() < end:
                ticks.append(1)
                time.sleep(0.1)
            stop_event.set()
        elapsed = time.perf_counter() - start
        print(f"{'threaded' if threaded else 'sequential'}: {len(ticks)} ticks, stopped cleanly")
        return elapsed

    seq_time = run(threaded=False)
    thr_time = run(threaded=True)
    return seq_time, thr_time

demos = [
    ("demo 1: basic threads",       run_demo1),
    ("demo 2: race condition",       run_demo2),
    ("demo 3: lock fix",             run_demo3),
    ("demo 4: threadpoolexecutor",   run_demo4),
    ("demo 5: event signalling",     run_demo5),
]

for name, demo in demos:
    print(f"\n{name}")
    seq, thr = demo()
    print(f"sequential: {seq:.3f}s  threaded: {thr:.3f}s  speedup: {seq/thr:.1f}x")
