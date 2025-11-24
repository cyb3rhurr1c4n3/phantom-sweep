"""
Argparse là gì? Là một module cho phép định nghĩa các đối số được truyền vào khi chạy chương trình
File này sẽ hướng dẫn về argparse!!!
"""
# import module
import argparse

# Tạo một đối tượng ArgumentParser
parser = argparse.ArgumentParser(description="**Chỗ này để mô tả chương trình**")

# Thêm đối số
parser.add_argument("name",help="Tên người dùng")

# Phân tích đối số
args=parser.parse_args()

# Sử dụng đối số
print(f"Hello, {args}")


# Các loại đối số
## Đối số bắt buộc (Không có tiền tố -- or -)
parser.add_argument("num1", type=int, help="Số thứ nhất")
parser.add_argument("num2", type=int, help="Số thứ 2")

args=parser.parse_args()
print(f"{args.num1} + {args.num2}=",args.num1+args.num2)

## Đối số không bắt buộc Optional (Có tiền tố -- or -)
parser.add_argument("--verbose",action="store_true",help="Hiển thị thông tin chi tiết")

args=parser.parse_args()
if args.verbosse:
    print("In ra thông tin chi tiết")
else:
    print("In ra thông tin bình thường")

# Các thuộc tính quan trọng với ** add_agrument()**
"""
- name or flag : Tên của đối số
- type : Kiểu dữ liệu đầu vào int or str,...
- default : Giá trị mặc định của đối số nếu không được cung cấp
- help : Mô tả đối số
- action : Hành động của đối số khi được cung cấp
    + store : Lưu giá trị 
    + store_true/store_false : lưu giá trị true hoặc false cho cờ 
    + append : Thêm giá trị vào danh sách
    + count : Đếm số lần xuất hiện của đối số
- nargs : Số lượng giá trị mà đối số nhận
    + N với N là số nguyên : Một số giá trị cố định
    + "+" : Một hoặc nhiều giá trị
    + "*" : Không giới 
- choice : Giới hạn giá trị trong một tập hợp
- dest : Tên biến lưu giá trị của đối số thay vì args.flag thì ta dùng 1 biến cho tường minh
"""
## Ví dụ
parser = argparse.ArgumentParser(description="Cal")

parser.add_argument("numbers",nargs="+",type=int,help="Danh sách các số nguyên")
parser.add_argument("--operation",choice= ["sum","max"],default="sum",action="store_true",help="Phép tính")

args=parser.parse_args()
if args.operation == "sum":
    print("Làm phép cộng")
    result=sum(args.numbers)
elif args.operation =="max":
    print("Làm phép max")
    result=max(args.numbers)

# Nâng cao
## Nhóm đối số (Argument Groups) được sủ dụng với --help ra cho đẹp 
input_group = parser.add_argument_group("Input options")
input_group.add_argument("--input", help="File đầu vào")
input_group.add_argument("--format", choices=["txt", "csv"], help="Định dạng file")

output_group = parser.add_argument_group("Output options")
output_group.add_argument("--output", help="File đầu ra")
output_group.add_argument("--overwrite", action="store_true", help="Ghi đè file")

args = parser.parse_args()
print(args)

## Xử lý đối số xung đột
## Dùng add_mutually_exclusive_group để đảm bảo chỉ một trong các đối số được chọn:
group = parser.add_mutually_exclusive_group()
group.add_argument("--save", action="store_true", help="Lưu file")
group.add_argument("--print", action="store_true", help="In ra màn hình")

args = parser.parse_args()
if args.save:
    print("Lưu file")
elif args.print:
    print("In ra màn hình")