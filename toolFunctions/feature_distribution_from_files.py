import os
from collections import Counter

import matplotlib.pyplot as plt


def feature_frequencies_per_file(feature_root_dir: str):
   
    feature_to_filecount = Counter()
    total_files = 0

    for dirpath, _, filenames in os.walk(feature_root_dir):
        for fname in filenames:
            if not fname.endswith(".txt"):
                continue

            total_files += 1
            full_path = os.path.join(dirpath, fname)

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    # Use a set so each feature in this file is counted once per file
                    features_in_this_file = set(
                        line.strip() for line in f if line.strip()
                    )
            except OSError as e:
                print(f"Warning: Could not read {full_path}: {e}")
                continue

            for feature in features_in_this_file:
                feature_to_filecount[feature] += 1

    return feature_to_filecount, total_files


def compute_count_distribution(feature_to_filecount: Counter) -> Counter:
    """
    Convert feature -> file_count into:
    """
    count_distribution = Counter()
    for file_count in feature_to_filecount.values():
        count_distribution[file_count] += 1
    return count_distribution


def save_distribution_to_file(distribution: Counter, output_path: str):
    
    if not distribution:
        print("Distribution is empty; nothing to save.")
        return

    max_count = max(distribution.keys())

    with open(output_path, "w", encoding="utf-8") as f:
        for count in range(1, max_count + 1):
            num_features = distribution.get(count, 0)
            if num_features:
                f.write(f"{count} : {num_features}\n")

    print(f"Wrote distribution to {output_path}")


def plot_distribution(distribution: Counter, output_path: str):
   
    if not distribution:
        print("Distribution is empty; nothing to plot.")
        return

    xs = sorted(distribution.keys())
    ys = [distribution[x] for x in xs]

    plt.figure(figsize=(10, 6))
    plt.bar(xs, ys)
    plt.xlabel("Number of files a feature appears in")
    plt.ylabel("Number of distinct features")
    plt.title("Feature Occurrence Distribution Across Files")
    plt.yscale("log")  # usually very skewed, log helps
    plt.grid(True, which="both", linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

    print(f"Wrote plot to {output_path}")


def main():
    # IMPORTANT: we want the updated dataset under example_features/
    feature_root_dir = r"..\extracted_features"
    out_dir = r".\exampleDocs"
    dist_text_filename = "feature_file_distribution.txt"
    dist_img_filename = "feature_file_distribution.png"

    print(f"Scanning feature files under: {feature_root_dir}")

    feature_to_filecount, total_files = feature_frequencies_per_file(
        feature_root_dir
    )

    print(f"Processed {total_files} .txt files.")
    print(f"Found {len(feature_to_filecount)} distinct features.")

    distribution = compute_count_distribution(feature_to_filecount)

    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    save_distribution_to_file(distribution, os.path.join(out_dir, dist_text_filename))
    plot_distribution(distribution, os.path.join(out_dir, dist_img_filename))

    print("Done.")


if __name__ == "__main__":
    main()

