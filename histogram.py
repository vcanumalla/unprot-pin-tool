import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import matplotlib.colors as mcolors

# Load CSV
df = pd.read_csv("ref.csv")
df.columns = df.columns.str.strip()
df['Count'] = df['Count'].astype(int)

# Sort full data
df_sorted = df.sort_values(by='Count').reset_index(drop=True)

# Extract address prefix (e.g., '0x401') for coloring
df_sorted['Prefix'] = df_sorted['Instruction Address'].str.slice(0, 5)

# Define unique prefixes and color map
prefixes = [f'0x40{i}' for i in range(1, 9)]
colors = cm.get_cmap('tab10', len(prefixes))
prefix_to_color = {prefix: colors(i) for i, prefix in enumerate(prefixes)}

# Assign a color for each row, defaulting to gray if prefix not in range
df_sorted['Color'] = df_sorted['Prefix'].map(prefix_to_color).fillna('gray')

# Reference lines
ref_lines = [1e6, 1e7, 1e8, 1e9]

def plot_histogram(data, title, filename):
    plt.figure(figsize=(12, 6))
    bar_colors = data['Color'].values
    plt.bar(range(len(data)), data['Count'], color=bar_colors)
    plt.yscale('log')  # log scale for better visibility

    for ref in ref_lines:
        plt.axhline(y=ref, linestyle=':', color='gray', linewidth=1)
        plt.text(0, ref, f"{int(ref):,}", va='bottom', ha='left', fontsize=8, color='gray')

    plt.xticks([])
    plt.ylabel("Execution Count (log scale)")
    plt.title(title)
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    plt.close()

# Plot all instructions
plot_histogram(df_sorted, "Instruction Execution Frequency (All Instructions)", "instruction_histogram_all_colored.png")

# Plot filtered instructions (Count > 10)
df_filtered = df_sorted[df_sorted['Count'] > 100000].reset_index(drop=True)
plot_histogram(df_filtered, "Instruction Execution Frequency (Count > 100000 Only)", "instruction_histogram_gt10_colored.png")