"""
File này sẽ hướng dẫn cơ bản về làm việc với file 
"""

# Làm việc với file

## Đọc
with open("file.txt","r",encoding='utf-8') as file:
    content=file.read()
    print(content)

with open("file.txt","r",encoding='utf-8') as file:
    for line in file:
        print(line.strip())

## Ghi
### Ghi đè
with open("file.txt","w",encoding='utf-8') as file:
    file.write("Hello world!")
### Chèn vào cuối file
with open("file.txt","a",encoding='utf-8') as file:
    file.write("Hello world!")

# Làm việc với file json
import json
## Đọc
with open("file.json","r",encoding='utf-8') as file:
    data=json.load(file)
    print(data) # Dữ liệu đã được chuyển thành Dict/List

## Ghi
data = {
    'name': 'Nguyen Van A',
    'age': 30,
    'city': 'Hanoi'
}

### Ghi vào file JSON
with open('data.json', 'w', encoding='utf-8') as file:
    json.dump(data, file, ensure_ascii=False, indent=4)

# Làm việc với file csv
import csv

## Đọc
with open('file.cvs','r',encoding='utf-8') as file:
    reader=csv.reader(file)
    header=next(file)
    for row in reader:
        print(row) # Mỗi row là một list

## Ghi

data = [
    ['Name', 'Age', 'City'],
    ['Nguyen Van A', 30, 'Hanoi'],
    ['Tran Thi B', 25, 'HCM']
]

with open('file.csv','w',encoding='utf-8') as file:
    writer=csv.writer(file)
    for row in data:
        writer.writerow(row)

## Dùng pandas đễ xử lý
import pandas as pd

file=pd.read_csv('file.csv')

file.to_csv('output.csv',encoding='utf-8',index=False)


# Xử lý lỗi với file
try:
    with open('file.txt','r',encoding='utf-8') as file:
        data=file.read()
        print(data)
except FileNotFoundError :
    print("File not Found")
except FileExistsError :
    print("Mở file có lỗi")
except PermissionError :
    print("Không có quyền truy cập file")
except Exception as e:
    print(f"Lỗi: {e}")