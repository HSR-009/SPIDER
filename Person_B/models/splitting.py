import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

def split_dataset_by_package(df: pd.DataFrame, group_col: str = "package_name", target_col: str = "label", test_size: float = 0.2, random_state: int = 42):
    """
    Splits feature table ensuring all versions/variants of the same package 
    belong exclusively to either the training set or the testing set.
    """
    if group_col not in df.columns:
        raise ValueError(f"Column '{group_col}' missing from dataset. Cannot perform group split.")

    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(splitter.split(df, groups=df[group_col]))

    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()

    # Integrity verification: Assert zero package leakage between splits
    train_pkgs = set(train_df[group_col])
    test_pkgs = set(test_df[group_col])
    overlap = train_pkgs.intersection(test_pkgs)

    if overlap:
        raise AssertionError(f"Data leakage detected! Packages present in both sets: {overlap}")

    return train_df, test_df

if __name__ == "__main__":
    # Quick sanity check with simulated versioned packages
    mock_data = pd.DataFrame({
        "package_name": ["pkg_alpha", "pkg_alpha", "pkg_beta", "pkg_gamma", "pkg_gamma"],
        "package_version": ["1.0", "1.1", "0.1", "2.0", "2.1"],
        "feat_eval_ratio": [0.1, 0.12, 0.0, 0.5, 0.48],
        "label": [1, 1, 0, 1, 1]
    })

    train, test = split_dataset_by_package(mock_data)
    print(f"Train packages: {train['package_name'].unique().tolist()}")
    print(f"Test packages:  {test['package_name'].unique().tolist()}")