import random
class Zipf:
    def __init__(self, n, s):
        # Commulative probabilities
        self.c_probs = [0.0 for i in range(n+1)]
        # Harmonic
        h = 0
        # Also called alpha
        self.s = s
        #  Number of ranks
        self.n = n

        for i in range(1, n+1):
            h += 1.0 / (i ** s)

        self.c_probs[0] = 0
        for i in range(1, n+1):
            self.c_probs[i] = self.c_probs[i - 1] + (1.0 / ((i ** s) * h));

    def sample(self):
        rnd = random.random()
        low = 1
        high = self.n
        while low <= high:
            mid = int((low + high) / 2)
            if rnd > self.c_probs[mid - 1] and rnd <= self.c_probs[mid]:
                return mid
            if self.c_probs[mid] < rnd:
                low = mid + 1
            else:
                high = mid - 1
        raise Exception('This must not happen')


