#!/bin/sh
gnuplot << EOF

set terminal pdfcairo size 4,2.5 font "Gill Sans,18" linewidth 4 rounded

# Line style for axes
set style line 80 lt rgb "#808080"

# Line style for grid
set style line 81 lt 0  # dashed
set style line 81 lt rgb "#808080"  # grey

set grid back linestyle 81
set border 15 back linestyle 80 #lc rgb "#808080" lt 1 # Remove border on top and right.  These
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

set ylabel "Probability of \nDiscovering Equivocation" offset 2
set xlabel "Number of Checks Performed" offset 0,0.5
set xtics nomirror right 

set key bottom right

set yrange [0:1]

set bmargin 3
set rmargin 1
#set logscale x

z(x,y) = 2*x/(y>x?0:(x - y))

f(p,k) = 1-(p+(1-p)*0.5)**(2*k)

plot [0:10] \
f(.01, x) w l t " 1\% Colluding Providers" lc rgbcolor blue_025 lw 2, \
f(.1, x) w lp  t "10\% Colluding Providers" lc rgbcolor green_025 pi -10 pt 4 lw 2, \
f(.5, x) w lp  t "50\% Colluding Providers" lc rgbcolor red_025 pi -10 pt 6 lw 2#, \
#f(x, 2) t "k = 2" lc rgbcolor red_025 lw 2
