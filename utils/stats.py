import csv
import sys
from statistics import mean, stdev


def compute_stats(csv_file):
    """
    Reads a CSV file and returns the mean and stdev for each numeric column.
    
    Args:
        csv_file: Path to the CSV file
        
    Returns:
        Dictionary with column names as keys and (mean, stdev) tuples as values
    """
    data = {}
    
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            for col, value in row.items():
                if col not in data:
                    data[col] = []
                try:
                    data[col].append(float(value))
                except ValueError:
                    pass
    
    stats = {}
    for col, values in data.items():
        if len(values) > 1:
            stats[col] = {
                'mean': mean(values),
                'stdev': stdev(values)
            }
        elif len(values) == 1:
            stats[col] = {
                'mean': values[0],
                'stdev': 0
            }
    
    return stats


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python stats.py <csv_file>")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    stats = compute_stats(csv_file)
    
    columns = " & ".join(stats.keys())
    print(columns)
    
    output = " & ".join(f"{col_stats['mean']:.3f} ({col_stats['stdev']:.3f})" for col_stats in stats.values())
    print(output)
