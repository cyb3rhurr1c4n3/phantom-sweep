1. Đặt tên ý nghĩa (Meaningful Naming)

Sử dụng tên biến, hàm, lớp rõ ràng, mô tả đúng chức năng.

    Biến: user_count, total_price thay vì n, t.
    Hàm: calculate_total_price() thay vì calc().
    Lớp: CustomerDatabase thay vì DB.


Tuân theo quy ước đặt tên của Python:

    Biến và hàm: snake_case (chữ thường, dấu gạch dưới).
    Lớp: PascalCase.
    Hằng số: UPPER_SNAKE_CASE.


Tránh tên viết tắt hoặc không rõ ràng.

    Xấu: tmp_val, fn.
    Tốt: temporary_value, process_data().



Ví dụ:
# Xấu
    def calc(x, y):
        return x * y

# Tốt
def calculate_area(width, height):
    return width * height
2. Hàm ngắn và làm một việc (Single Responsibility)

Mỗi hàm chỉ nên làm một việc duy nhất.

    Hàm nên ngắn, lý tưởng là dưới 15-20 dòng.
    Tách logic phức tạp thành các hàm nhỏ hơn.


Giới hạn số lượng tham số (tối đa 3-4).

    Nếu cần nhiều tham số, sử dụng đối tượng hoặc từ khóa (**kwargs).


Sử dụng hàm thuần túy (pure functions) khi có thể.

    Cùng đầu vào luôn cho cùng đầu ra, không có tác dụng phụ.



Ví dụ:
# Xấu
def process_user_data(name, age, email, db):
    # Lấy dữ liệu, kiểm tra, lưu vào DB
    if name and age > 0:
        db.save({"name": name, "age": age, "email": email})

# Tốt
def validate_user_data(name, age):
    return name and age > 0

def save_user_to_db(name, age, email, db):
    user = {"name": name, "age": age, "email": email}
    db.save(user)
3. Bình luận và Docstring

Sử dụng docstring (PEP 257) để mô tả hàm, lớp, mô-đun.

    Docstring đặt trong """ """, mô tả mục đích, tham số, giá trị trả về.


Chỉ bình luận khi cần giải thích "tại sao" thay vì "cái gì".

    Tránh bình luận dư thừa, vì mã tốt tự giải thích.


Cập nhật docstring khi mã thay đổi.

Ví dụ:
# Xấu
def add(a, b):  # Cộng hai số
    return a + b

# Tốt
def add_numbers(a: int, b: int) -> int:
    """Add two numbers and return their sum.
    
    Args:
        a (int): First number.
        b (int): Second number.
    
    Returns:
        int: Sum of the two numbers.
    """
    return a + b
4. Định dạng mã (Formatting - PEP 8)

Sử dụng 4 khoảng trắng để thụt lề.

    Không dùng tab.


Giới hạn độ dài dòng tối đa 79 ký tự (hoặc 120 nếu đội nhóm đồng ý).
Thêm dòng trống để phân tách logic.

    2 dòng trống trước/sau định nghĩa hàm hoặc lớp.
    1 dòng trống giữa các khối logic trong hàm.


Sắp xếp import theo thứ tự:

    Thư viện chuẩn (standard library).
    Thư viện bên thứ ba.
    Mô-đun nội bộ.


Ví dụ:
import os
import sys

import numpy as np

from my_module import my_function




Ví dụ:
# Xấu
def process_data(data): 
    result= []
    for i in data:result.append(i*2)
    return result

# Tốt
def process_data(data: list) -> list:
    """Double each element in the input list."""
    result = []
    for item in data:
        result.append(item * 2)
    return result
5. Xử lý lỗi (Error Handling)

Sử dụng try-except để bắt lỗi cụ thể.

    Tránh except: chung chung, chỉ bắt các ngoại lệ cụ thể như ValueError, TypeError.


Trả về thông báo lỗi rõ ràng hoặc giá trị mặc định.
Sử dụng logging thay vì print để ghi lỗi.

Ví dụ:
# Xấu
def divide(a, b):
    try:
        return a / b
    except:
        return None

# Tốt
import logging

def divide_numbers(a: float, b: float) -> float:
    """Divide two numbers and handle division by zero."""
    try:
        return a / b
    except ZeroDivisionError:
        logging.error("Division by zero attempted")
        return 0.0
6. Tách biệt logic (Separation of Concerns)

Tách logic giao diện, kinh doanh, và dữ liệu.

    Ví dụ: Sử dụng mô hình MVC hoặc tách logic vào các mô-đun riêng.


Sử dụng mô-đun và gói (package) để tổ chức mã.

    Ví dụ: Thư mục models/, utils/, services/.


Tránh mã "thần thánh" (god object) chứa tất cả logic.

Ví dụ:
# Xấu: Tất cả trong một file
def get_data():
    # Lấy dữ liệu
    pass

def process_data():
    # Xử lý
    pass

# Tốt: Tách thành các mô-đun
# data/fetch.py
def fetch_data():
    """Retrieve data from the database."""
    pass

# data/process.py
def process_data(data):
    """Process the input data."""
    pass
7. Kiểm thử (Testing)

Viết mã dễ kiểm thử.

    Sử dụng hàm thuần túy, tránh trạng thái toàn cục (global state).


Sử dụng thư viện như unittest, pytest để viết unit test.
Kiểm tra các trường hợp biên (edge cases).

Ví dụ:
python# Hàm cần kiểm thử
def calculate_discount(price: float, discount_rate: float) -> float:
    return price * (1 - discount_rate)

# Unit test với pytest
def test_calculate_discount():
    assert calculate_discount(100, 0.2) == 80.0
    assert calculate_discount(100, 0) == 100.0
    assert calculate_discount(0, 0.2) == 0.0
8. Tránh mã phức tạp (Simplicity)

Ưu tiên mã đơn giản, dễ hiểu.

    Sử dụng list comprehension thay vì vòng lặp phức tạp khi phù hợp.
    Ví dụ: [x * 2 for x in numbers] thay vì vòng lặp for.


Không tối ưu hóa sớm.

    Chỉ tối ưu khi có bằng chứng về vấn đề hiệu suất.



Ví dụ:
# Xấu
result = []
for i in range(len(numbers)):
    if numbers[i] > 0:
        result.append(numbers[i] * 2)

# Tốt
result = [num * 2 for num in numbers if num > 0]
9. Sử dụng Type Hint

Thêm type hint (PEP 484) để tăng tính rõ ràng.

Sử dụng typing module cho các kiểu phức tạp như List, Dict.


Kiểm tra type hint với công cụ như mypy.

Ví dụ:
pythonfrom typing import List

def filter_positive_numbers(numbers: List[int]) -> List[int]:
    return [num for num in numbers if num > 0]
10. Quản lý phụ thuộc (Dependency Management)

Sử dụng môi trường ảo (venv, virtualenv).
Ghi rõ phụ thuộc trong requirements.txt.
Tránh sử dụng biến toàn cục hoặc phụ thuộc ẩn.

Ví dụ:
# requirements.txt
    requests==2.28.1
    pytest==7.4.0
11. Sử dụng công cụ hỗ trợ

Linter: flake8, pylint để kiểm tra lỗi và định dạng.
Formatter: black, autopep8 để tự động định dạng mã theo PEP 8.
Type checker: mypy để kiểm tra type hint.

Ví dụ sử dụng black:
bashblack my_script.py
12. Tái cấu trúc và xem xét mã

Thường xuyên tái cấu trúc (refactor) để cải thiện mã.

    Ví dụ: Tách hàm lớn thành các hàm nhỏ hơn.


Thực hiện code review.

    Sử dụng công cụ như GitHub Pull Requests để đồng nghiệp kiểm tra mã.



Ví dụ tổng hợp
Mã xấu:
pythondef proc(d): # Xử lý dữ liệu
    r = []
    for i in d:
        if i>0:r.append(i*2)
    return r

# main.py
print(proc([1, -2, 3]))
Mã sạch:
pythonfrom typing import List

def double_positive_numbers(numbers: List[int]) -> List[int]:
    """Double all positive numbers in the input list.
    
    Args:
        numbers (List[int]): List of integers to process.
    
    Returns:
        List[int]: List of doubled positive numbers.
    """
    return [num * 2 for num in numbers if num > 0]

# main.py
if __name__ == "__main__":
    numbers = [1, -2, 3]
    result = double_positive_numbers(numbers)
    print(result)