#!/bin/sh
gnuplot << EOF
# Note you need gnuplot 4.4 for the pdfcairo terminal.

set terminal pdfcairo size 4,2 font "Gill Sans,24" linewidth 4 rounded

# Line style for axes
set style line 80 lt rgb "#808080"

# Line style for grid
set style line 81 lt 0 # dashed
set style line 81 lt rgb "#808080" # grey
set grid back linestyle 81
set border 15 back linestyle 80 # Remove border on top and right. These

# borders are useless and make it harder
# to see plotted lines near the border.
# Also, put it in grey; no need for so much emphasis on a border.

set xtics nomirror
set ytics nomirror
red_000 = "#F9B7B0"
red_025 = "#F97A6D"
red_050 = "#E62B17"
red_075 = "#8F463F"
red_100 = "#6D0D03"
blue_000 = "#A9BDE6"
blue_025 = "#7297E6"
blue_050 = "#1D4599"
blue_075 = "#2F3F60"
blue_100 = "#031A49"
green_000 = "#A6EBB5"
green_025 = "#67EB84"
green_050 = "#11AD34"
green_075 = "#2F6C3D"
green_100 = "#025214"
brown_000 = "#F9E0B0"
brown_025 = "#F9C96D"
brown_050 = "#E69F17"
brown_075 = "#8F743F"
brown_100 = "#6D4903"

# Line styles: try to pick pleasing colors, rather
# than strictly primary colors or hard-to-see colors
# like gnuplot's default yellow. Make the lines thick
# so they're easy to see in small plots in papers.

set style line 1 linecolor rgbcolor blue_050 lw 2 ps 1 pt 6
set style line 2 linecolor rgbcolor red_050 lt 0 lw 3
set style line 3 linecolor rgbcolor green_050 lt 0 lw 3
set style line 4 linecolor rgbcolor blue_025 lw 2
set style line 5 linecolor rgbcolor red_025 lw 2
set style line 6 linecolor rgbcolor green_025 lw 2
set style line 7 linecolor rgbcolor red_050 lw 2
set style line 8 linecolor rgbcolor brown_050 lw 2

set output "/tmp/verify-latency-cdf-plot.pdf"

set ylabel "Proportion" offset 2
set xlabel "Latency (microseconds)" offset 1

#set key outside horiz center bottom
#set xrange [0:100]
#set yrange [0:35]

set ytics .25
set yrange [0:1]

set bmargin 3
set rmargin 2
#set lmargin 8

# col 1 -> x, col 2 -> y, col 3 -> ydelta (stdev)

plot '/tmp/latency-verify-2k-us-cdf.csv' u 1:2 notitle w l ls 1

EOF
