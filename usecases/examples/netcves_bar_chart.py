#!/usr/bin/env python3
import matplotlib.pyplot as plt
from typing import Tuple


def parse_line(line: str) -> Tuple[int, str]:
    year, cve = line.strip().split(',', 1)
    return year, cve


def read_cve_csv(file: str) -> dict:
    res = dict()
    with open(file) as fp:
        for year, cve in map(parse_line, fp):
            res[year] = res.get(year, 0) + 1
    return res


def main() -> int:
    netcves_by_years = read_cve_csv('netcves_by_years.csv')
    netcves_by_years.pop('2024', None) # remove current year because of no data

    # Set default figure size.
    plt.rcParams['figure.figsize'] = (8, 5)
    fig, ax = plt.subplots()

    # Save the chart so we can loop through the bars below.
    bars = ax.bar(
        x=range(len(netcves_by_years)),
        height=netcves_by_years.values(),
        tick_label=list(netcves_by_years.keys())
    )

    # First, let's remove the top, right and left spines (figure borders)
    # which really aren't necessary for a bar chart.
    # Also, make the bottom spine gray instead of black.
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    ax.spines['bottom'].set_color('#DDDDDD')

    # Second, remove the ticks as well.
    ax.tick_params(bottom=False, left=False, labelsize=14)

    # Third, add a horizontal grid (but keep the vertical grid hidden).
    # Color the lines a light gray as well.
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color='#EEEEEE')
    ax.xaxis.grid(False)

    # Grab the color of the bars so we can make the
    # text the same color.
    bar_color = bars[0].get_facecolor()
    # Add text annotations to the top of the bars.
    # Note, you'll have to adjust this slightly (the 0.3)
    # with different data.
    for bar in bars:
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            round(bar.get_height(), 1),
            horizontalalignment='center',
            color=bar_color,
            weight='bold',
            fontsize=20,
        )

    # Add labels and a title. Note the use of `labelpad` and `pad` to add some
    # extra space between the text and the tick labels.
    ax.set_xlabel('Год обнаружения уязвимостей', labelpad=5, color='#333333',
                  fontsize=20)
    ax.set_ylabel('Число уязвимостей в сетевых протоколах', labelpad=5,
                  color='#333333', fontsize=20)
    ax.set_title('Найденное число уязвимостей в сетевых протоколах по годам [2003-2023]',
                 pad=5, color='#333333', weight='bold', fontsize=20)

    fig.tight_layout()
    plt.show()
    return 0


if __name__ == '__main__':
    exit(main())
