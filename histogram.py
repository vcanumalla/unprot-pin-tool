import pandas as pd
import matplotlib.pyplot as plt

# Load CSV
df = pd.read_csv("ref.csv")
df.columns = df.columns.str.strip()
df['Count'] = df['Count'].astype(int)

# Sort full data by Count
df_sorted = df.sort_values(by='Count').reset_index(drop=True)

# Reference lines
ref_lines = [1e6, 1e7, 1e8, 1e9]

def plot_histogram(data, title, filename):
    plt.figure(figsize=(12, 6))
    plt.bar(range(len(data)), data['Count'])
    plt.yscale('log')
    for ref in ref_lines:
        plt.axhline(y=ref, linestyle=':', color='gray', linewidth=1)
        plt.text(0, ref, f"{int(ref):,}", va='bottom', ha='left', fontsize=8, color='gray')
    plt.xticks([])
    plt.ylabel("Execution Count")
    plt.title(title)
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    plt.close()

# Plot all instructions
plot_histogram(df_sorted, "Instruction Execution Frequency (All Instructions)", "instruction_histogram_all.png")

# Plot filtered (Count > 10)
df_filtered = df_sorted[df_sorted['Count'] > 100000].reset_index(drop=True)
plot_histogram(df_filtered, "Instruction Execution Frequency (Count > 10 Only)", "instruction_histogram_gt10.png")