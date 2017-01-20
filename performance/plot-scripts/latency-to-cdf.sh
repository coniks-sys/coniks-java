sort -n ../data/latency-verify-2k-ns.csv | awk '
{	d[++c] = $0
}
END {	inc = 1 / c
	for(i = 0; i <= c; i++)
		printf("%.1f,\t\t%.6f\n", d[i]/1000, i * inc)
}' > /tmp/latency-verify-2k-us-cdf.csv
