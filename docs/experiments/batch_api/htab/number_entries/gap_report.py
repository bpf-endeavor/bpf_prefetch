#! python3
orange= [3420, 3402.22, 3179.56, 2738.33, 2652.78, 2588.0, 2573.67, 2538.67, 2456.44, 2500.0, 2466.78, 2438.11]
blue= [3679.44, 3397.56, 3021.89, 2384.44, 2271.56, 2242.78, 2181.0, 2133.22, 2160.44, 2040.44, 2062.11, 1977.78]
black= [2505.22, 2771.78, 2313.11, 1899.33, 1868.67, 1820.44, 1893.22, 1722.78, 1775.11, 1663.67, 1574.22, 1774.22]

def delta_p(A, B):
    t = [(b-a)/a*100 for a,b in zip(A,B)]
    t = [round(f, ndigits=1) for f in t]
    return t


T = delta_p(black, blue)
print('baselin - batch:', T)
print(f'max: {max(T)}   min: {min(T)}')

T = delta_p(blue, orange)
print('batch - batch + pf:', T)
print(f'max: {max(T)}   min: {min(T)}')

