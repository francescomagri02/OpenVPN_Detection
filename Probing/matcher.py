import json
import os

def load_all_patterns(pattern_dir="./patterns/"):
    patterns = []

    for filename in os.listdir(pattern_dir):
        if filename.endswith(".json"):
            path = os.path.join(pattern_dir, filename)
            with open(path, "r") as f:
                pattern_data = json.load(f)
                patterns.append(pattern_data)
    
    return patterns

def normalize_sequence(seq):
    return [s.strip().lower() for s in seq]

def match_result_to_patterns(result_sequence, patterns):
    result_statuses = [res["status"] for res in result_sequence]
    norm_result = normalize_sequence(result_statuses)

    best_match = None
    min_mismatches = len(norm_result) + 1  # initialize with the maximum possible

    for pattern in patterns:
        norm_pattern = normalize_sequence(pattern["expected_sequence"])

        # Skip if sequences are not the same length
        if len(norm_pattern) != len(norm_result):
            continue

        mismatches = sum(1 for a, b in zip(norm_pattern, norm_result) if a != b)

        if mismatches < min_mismatches:
            min_mismatches = mismatches
            best_match = pattern["name"]

    if best_match is not None:
        if min_mismatches == 0:
            return best_match
        else:
            return f"{best_match} (tolerance: {min_mismatches} mismatch)"

    return "Unknown"
