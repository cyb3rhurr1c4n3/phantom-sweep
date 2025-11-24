"""
File sẽ hướng dẫn về việc sử dụng threading
"""
# import module
import threading

"""
Khái niệm cơ bản:
    1. Thread : một đơn vị thực thi nhỏ nhất trong 1 tiến trình. Có thể thực thi nhiều thread cùng lúc, chạy các hàm riêng biệt.
    2. Main Thread : Luồng chính của chương trình
    3. Daemon : Luồng chạy ngầm
    4. Synchronization : Các cộng cụ để tránh race condition
"""
# Cách tạo và chạy thread

import time

def worker():
    print("Worker starting")
    time.sleep(2)
    print("Worker finishing")

threads=[] # Tạo danh sách các thread

for i in range(3):
    t=threading.Thread(target=worker)
    threads.append(t)
    t.start()

for t in threads:
    t.join() # Nếu không main thread sẽ kết thúc trước

print("ALL worker done!")

# Truyền tham số cho thread
def worker(name,age):
    print(f"My name is {name} and i am {age} years old")


t=threading.Thread(target=worker,args=("Alice",18))
t.start()
t.join()
print("Done")


# Daemon Thread
"""
Daemon thread dừng khi chương trình kết thúc
Đặt Daemon=True khi tạo
"""
## Ví dụ
def daemon_worker():
    print("Daemon thread starting")
    time.sleep(5)
    print("Daemon thread finishing")

t=threading.Thread(target=daemon_worker,daemon=True)
t.start()

"""
Nó chỉ in ra {Daemon thread starting} vì nó chạy ngầm mà tiến trình Main Thread kết thúc nên nó buộc phải kết thúc
"""

# Synchronization: Tránh Race Condition
## Ví dụ race condition (không an toàn):
counter = 0

def increment():
    global counter
    for _ in range(100000):  # Tăng 100.000 lần
        counter += 1  # Có thể bị gián đoạn giữa các threads

threads = []
for i in range(5):  # 5 threads
    t = threading.Thread(target=increment)
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print(counter)  # Nên là 500.000, nhưng có thể ít hơn do race (ví dụ: 456.789)

## Giải pháp: Sử dụng Lock
import threading

counter = 0
lock = threading.Lock()  # Tạo lock

def increment():
    global counter
    for _ in range(100000):
        with lock:  # Acquire và release tự động
            counter += 1

threads = []
for i in range(5):
    t = threading.Thread(target=increment)
    threads.append(t)
    t.start()

for t in threads:
    t.join()

print(counter)  # Luôn là 500.000

## Các Synchronization Khác
### Condition: Dùng để threads chờ một điều kiện (kết hợp với Lock).
import threading

condition = threading.Condition()
shared_data = None

def producer():
    global shared_data
    with condition:
        shared_data = "Data produced"
        condition.notify()  # Thông báo consumer

def consumer():
    with condition:
        condition.wait()  # Chờ producer
        print(shared_data)

t1 = threading.Thread(target=producer)
t2 = threading.Thread(target=consumer)
t2.start()  # Consumer chờ trước
t1.start()
t1.join()
t2.join()

### Semaphore: Giới hạn số lượng threads truy cập tài nguyên (như giới hạn kết nối DB).
import threading
import time

semaphore = threading.Semaphore(2)  # Giới hạn 2 threads cùng lúc

def access_resource():
    with semaphore:
        print("Accessing resource")
        time.sleep(1)
        print("Releasing resource")

threads = [threading.Thread(target=access_resource) for _ in range(5)]
for t in threads:
    t.start()
for t in threads:
    t.join()


# Ví dụ Nâng Cao: Tải Dữ Liệu Song Song
import threading
import time

def fecth(url):
    print("request to url")
    time.sleep(5)
    print("Done")

urls =["url1.com","url2.com","url3.com"]
threads=[]
for url in urls:
    t=threading.Thread(target=fecth,args=(url,)) # args mong muốn 1 kiểu tuple, nếu chỉ là url nó sẽ tưởng tưởng là giá trị url và tách từng phần tử ra thành 1 list char 
    threads.append(t)
for t in threads:
    t.start()
for t in threads:
    t.join()

print("Done")