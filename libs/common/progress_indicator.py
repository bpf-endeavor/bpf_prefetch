class ProgIndicator:
    def __init__(self):
        self.prime()

    def prime(self):
        self.state = 0
        self.count = 0
        self.first = True

    def out(self):
        print('\r                    ')

    def __call__(self):
        x = '/-\|-\|'
        c = x[self.state]
        self.count += 1
        self.state = (self.state + 1) % len(x)

        if self.count % (701) != 1:
            return

        if self.first:
            self.first = False
            s = f'\n{c}'
        else:
            s = f'\r{c}'
        s += f' {self.count}'
        print(s, end='', sep='')
