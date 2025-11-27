s="192.168.1.1-10"
result=list()
parts=s.split('.')
for part in parts:
    if '-' in part:
        start,end=map(int,part.split('-'))
        for i in range(start,end+1):
            tmp= f"{parts[0]}.{parts[1]}.{parts[2]}.{i}"
            result.append(tmp)

print(result)