import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import ast
from collections import Counter
from pathlib import Path

# Professional Styling for visualizations
plt.style.use('dark_background')
sns.set_theme(style="darkgrid", rc={"axes.facecolor": "#1e1e2f", "figure.facecolor": "#1e1e2f", "grid.color": "#2c2c3e", "text.color": "white", "axes.labelcolor": "white", "xtick.color": "white", "ytick.color": "white"})

def parse_rules(rule_str):
    if pd.isna(rule_str) or rule_str == "":
        return []
    # rules are currently saved as a comma separated string: RUG-FP4, RUG-FP5 or as a python list string
    if rule_str.startswith("["):
        try:
            return ast.literal_eval(rule_str)
        except:
            return []
    else:
        return [r.strip() for r in rule_str.split(",") if r.strip()]

def main():
    print("=" * 80)
    print(" [~] BLOCKCHAIN INVESTIGATOR: RUGPULL FORENSICS BATCH ANALYSIS ")
    print("=" * 80)
    
    data_file = Path("fast_batch_results.csv")
    if not data_file.exists():
        print(f"[!] Error: Data file '{data_file}' not found. Please run the batch test first.")
        return
        
    df = pd.read_csv(data_file)
    total_wallets = len(df)
    print(f"\n[+] Loaded {total_wallets} addresses from {data_file.name}")
    
    # Clean data (filter out ERROR rows which were timeouts/crashes)
    df_valid = df[~df['Rugpull Verdict'].isin(['ERROR', 'TIMEOUT'])]
    valid_count = len(df_valid)
    print(f"[+] Found {valid_count} successfully processed wallets.\n")
    
    # 1. Verdict Distribution
    verdict_counts = df_valid['Rugpull Verdict'].value_counts()
    
    # Calculate detection metrics
    detected = df_valid[df_valid['Rugpull Verdict'].isin(['HIGH_CONFIDENCE_RUGPULL', 'STRONG_PATTERN', 'MODERATE_PATTERN', 'WEAK_PATTERN'])]
    missed = df_valid[df_valid['Rugpull Verdict'] == 'CLEAN']
    insufficient = df_valid[df_valid['Rugpull Verdict'] == 'INSUFFICIENT_DEPLOYMENT_HISTORY']
    
    detection_rate = (len(detected) / valid_count) * 100
    
    print("-" * 40)
    print(f" [!] PERFORMANCE METRICS")
    print("-" * 40)
    print(f"  • True Positives (Detected) : {len(detected)} ({detection_rate:.1f}%)")
    print(f"  • False Negatives (Missed)  : {len(missed)} ({(len(missed)/valid_count)*100:.1f}%)")
    print(f"  • Insufficient History      : {len(insufficient)} ({(len(insufficient)/valid_count)*100:.1f}%)\n")
    
    print("  Breakdown by Severity:")
    for v, count in verdict_counts.items():
        print(f"    - {v.ljust(30)}: {count}")
        
    # Plot 1: Verdict Distribution
    plt.figure(figsize=(10, 6))
    ax = sns.barplot(x=verdict_counts.values, y=verdict_counts.index, palette="viridis")
    plt.title("Distribution of Rugpull Verdicts", fontsize=16, pad=15)
    plt.xlabel("Number of Wallets", fontsize=12)
    plt.ylabel("Verdict", fontsize=12)
    plt.tight_layout()
    plt.savefig("analysis_verdicts.png", dpi=300)
    
    # 2. Rule Frequency Analysis
    all_rules = []
    for rules_str in df_valid['Triggered Rules']:
        all_rules.extend(parse_rules(rules_str))
        
    rule_counts = Counter(all_rules)
    rule_df = pd.DataFrame(rule_counts.items(), columns=['Rule ID', 'Count']).sort_values('Count', ascending=False)
    
    print("\n" + "-" * 40)
    print(f" [!] TOP TRIGGERED FORENSIC RULES")
    print("-" * 40)
    for idx, row in rule_df.head(8).iterrows():
        print(f"  • {row['Rule ID'].ljust(15)} : Triggered {row['Count']} times")
        
    # Plot 2: Top Triggered Rules
    plt.figure(figsize=(12, 6))
    ax = sns.barplot(x='Count', y='Rule ID', data=rule_df.head(10), palette="magma")
    plt.title("Most Frequent Rugpull Indicators (Top 10)", fontsize=16, pad=15)
    plt.xlabel("Frequency Across Wallets", fontsize=12)
    plt.ylabel("Rule ID", fontsize=12)
    plt.tight_layout()
    plt.savefig("analysis_rules.png", dpi=300)
    
    # 3. Score Distribution
    # Convert scores to numeric
    df_valid.loc[:, 'Rugpull Score'] = pd.to_numeric(df_valid['Rugpull Score'], errors='coerce')
    
    print("\n" + "-" * 40)
    print(f" [!] SCORE STATISTICS")
    print("-" * 40)
    mean_score = df_valid['Rugpull Score'].mean()
    median_score = df_valid['Rugpull Score'].median()
    print(f"  • Average Risk Score : {mean_score:.1f}/100")
    print(f"  • Median Risk Score  : {median_score:.1f}/100")
    
    # Plot 3: Score Histogram
    plt.figure(figsize=(10, 6))
    sns.histplot(data=df_valid, x='Rugpull Score', bins=20, kde=True, color="#00ffcc")
    plt.title("Distribution of Threat Scores", fontsize=16, pad=15)
    plt.xlabel("Rugpull Score (0-100)", fontsize=12)
    plt.ylabel("Number of Wallets", fontsize=12)
    
    # Add vertical lines for thresholds
    plt.axvline(20, color='yellow', linestyle='--', alpha=0.7, label='WEAK (20)')
    plt.axvline(36, color='orange', linestyle='--', alpha=0.7, label='MODERATE (36)')
    plt.axvline(50, color='red', linestyle='--', alpha=0.7, label='STRONG (50)')
    plt.axvline(75, color='darkred', linestyle='--', alpha=0.7, label='CRITICAL (75)')
    
    plt.legend()
    plt.tight_layout()
    plt.savefig("analysis_scores.png", dpi=300)
    
    print("\n" + "=" * 80)
    print(" [OK] ANALYSIS COMPLETE")
    print(" Visualizations saved to the current directory:")
    print("   1. analysis_verdicts.png")
    print("   2. analysis_rules.png")
    print("   3. analysis_scores.png")
    print("=" * 80)
    
    print("\n[!] Opening plots in GUI windows. Close the windows to exit.")
    plt.show()

if __name__ == "__main__":
    main()
