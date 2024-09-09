import json
a = input('a: ')
b = input('b: ')

a = json.loads(a)
b = json.loads(b)

c = [ round(((y - x) / x)*100, ndigits=2) for x, y in zip(a,b)]
print(c)
