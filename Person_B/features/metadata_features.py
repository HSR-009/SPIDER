import datetime
import requests
import Levenshtein

# Top popular packages frequently targeted by typosquatters
TARGET_POPULAR_PACKAGES = [
    "requests", "urllib3", "numpy", "pandas", "flask", "django",
    "setuptools", "pytest", "cryptography", "botocore", "certifi",
    "colorama", "wheel", "pip", "pillow", "six", "boto3", "scipy"
]

def compute_typosquat_distance(package_name: str) -> dict:
    """
    Finds the minimum Levenshtein distance between the package name 
    and known popular libraries, plus identifies the closest match.
    """
    if not package_name:
        return {"feat_min_edit_distance": 999, "feat_is_potential_squat": 0}

    cleaned_name = package_name.strip().lower()
    min_dist = min(Levenshtein.distance(cleaned_name, target.lower()) for target in TARGET_POPULAR_PACKAGES)

    # If the distance is 1 or 2, it's a high-probability typosquat candidate
    # Distance of 0 means it literally IS the legitimate package
    is_squat = 1 if min_dist in (1, 2) else 0

    return {
        "feat_min_edit_distance": int(min_dist),
        "feat_is_potential_squat": is_squat
    }

def fetch_pypi_metadata(package_name: str) -> dict:
    """
    Queries the official PyPI JSON API to extract release age and version count.
    Falls back safely with default values if the package is local or unreleased.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    defaults = {
        "feat_package_age_days": -1,
        "feat_total_releases": 0,
        "feat_pypi_exists": 0
    }

    try:
        response = requests.get(url, timeout=3)
        if response.status_code != 200:
            return defaults

        data = response.json()
        releases = data.get("releases", {})
        total_releases = len(releases)

        # Calculate package age from first release upload time
        upload_times = []
        for rel_version, files in releases.items():
            for file_info in files:
                if "upload_time_iso_8601" in file_info:
                    upload_times.append(file_info["upload_time_iso_8601"])

        age_days = -1
        if upload_times:
            upload_times.sort()
            first_upload = datetime.datetime.fromisoformat(upload_times[0].replace("Z", "+00:00"))
            now = datetime.datetime.now(datetime.timezone.utc)
            age_days = (now - first_upload).days

        return {
            "feat_package_age_days": max(age_days, 0),
            "feat_total_releases": total_releases,
            "feat_pypi_exists": 1
        }

    except requests.RequestException:
        return defaults


if __name__ == "__main__":
    # Test 1: Typosquatting detection
    test_legit = "requests"
    test_fake = "reqeusts"  # Typosquat
    print(f"Distance for '{test_legit}':", compute_typosquat_distance(test_legit))
    print(f"Distance for '{test_fake}':", compute_typosquat_distance(test_fake))

    # Test 2: Live PyPI API metadata lookup
    print("\nFetching metadata for 'flask'...")
    print(fetch_pypi_metadata("flask"))