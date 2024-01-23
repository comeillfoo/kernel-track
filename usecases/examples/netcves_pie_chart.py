#!/usr/bin/env python3
import matplotlib.pyplot as plt
import seaborn as sns


def main() -> int:
    cves_ratios = [830, 2590 - 830]
    cves_ratios_labels = ['Сетевые', 'Другие']

    # Increase the size of the plot
    plt.figure(figsize=(8,8))

    patches, texts, autotexts = plt.pie(
        x=cves_ratios,
        labels=cves_ratios_labels,
        # show percentage with two decimal points
        autopct='%1.2f%%',
        # increase the size of all text elements
        textprops={'fontsize': 14},
        # Use Seaborn's color palette 'Paired'
        colors=sns.color_palette('Paired'),
        startangle=85,
        # Add space around each slice
        explode=[0.05, 0.05]
    )

    # Add Title
    plt.title(
        label='Доля сетевых уязвимостей по данным LinuxKernelCVEs',
        fontdict={'fontsize': 16},
        pad=20
    )

    for text in texts:
        text.set_fontweight('bold')

    # Customize percent labels
    for autotext in autotexts:
        autotext.set_horizontalalignment('center')
        autotext.set_fontstyle('italic')

    plt.show()

    return 0


if __name__ == '__main__':
    exit(main())
