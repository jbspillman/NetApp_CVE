from downloader import download_cve_details
from parse_bulletins import (create_bulletins_products,
                             create_baseline_reports, find_open_advisories_by_version,
                             cleanup_old_dates)
import datetime
from datetime import timedelta
current_time_stamp = datetime.datetime.now()
date_stamp = current_time_stamp.strftime("%Y%m%d")
yesterday = current_time_stamp - timedelta(days=1)
date_minus_one = yesterday.strftime("%Y%m%d")

applications_to_watch = [
    {
        "application_name": "Active IQ Unified Manager for Microsoft Windows",
        "app_key": "AIQUM",
        "app_versions": []
    },
    {
        "application_name": "Clustered Data ONTAP",
        "app_key": "ONTAP",
        "app_versions": []
    },
    {
        "application_name": "ONTAP 9 (formerly Clustered Data ONTAP)",
        "app_key": "ONTAP",
        "app_versions": ["9.8.1.P18", "9.10.1P12"]
    }
]


def main():

    # download_cve_details()  # gets the data on the date of running script.
    # create_bulletins_products()  # ensures the bulletins and products json files exist.
    # create_baseline_reports(applications_to_watch)  # finds potential advisory based on product watched.
    # find_open_advisories_by_version(applications_to_watch)  # eliminates advisories which are no longer a concern.
    cleanup_old_dates()


if __name__ == '__main__':
    main()
