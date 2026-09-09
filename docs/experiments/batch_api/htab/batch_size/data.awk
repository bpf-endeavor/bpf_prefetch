function report() {
	if (count == 0) {
		return
	}
	avg = sum / count;
	arr[bs] = avg;
	printf "batch size: %d avg: %.2f\n", bs, avg;
}

BEGIN {
	bs = 0;
	sum = 0;
	count = 0;
}

/Batch/ {
	report()
	bs = $3;
	sum = 0;
	count = 0;
}

/throughput:/ { sum += $7; count++; }

END {
	report()
	for (i = 1; i <= bs; i++) {
		printf "%.2f,", arr[i];
	}
	printf "\n";
}
