import os
import re
import time
import json
import datetime
import pandas as pd
from datetime import datetime


def cleanhtml(raw_html):
    clean_html_regex = re.compile('<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});')
    clean_text = re.sub(clean_html_regex, '', raw_html)
    return clean_text


def rating_number(level):
    if level.upper() == 'CRITICAL':
        return 5
    elif level.upper() == 'HIGH':
        return 4
    elif level.upper() == 'MEDIUM':
        return 3
    elif level.upper() == 'LOW':
        return 2
    elif level.upper() == 'NONE':
        return 1
    else:
        return 0


def days_active(date_one, date_two):
    date_one = datetime.strptime(str(date_one), "%Y%m%d")
    date_two = datetime.strptime(str(date_two), "%Y%m%d")
    if date_two > date_one:
        return (date_two-date_one).days
    else:
        return (date_one-date_two).days


def create_bulletins_products(today):
    print("entered:".ljust(30), "create_bulletins_products")
    script_path = os.path.dirname(os.path.realpath(__file__))
    data_folder = os.path.join(script_path, 'data')
    ntap_bulletins_folder = os.path.join(data_folder, 'bulletins', today)

    all_bulletins_json = os.path.join(ntap_bulletins_folder, "ALL_BULLETINS.json")
    all_products_json = os.path.join(ntap_bulletins_folder, "ALL_PRODUCTS.json")
    if os.path.exists(all_bulletins_json) and os.path.exists(all_products_json):
        skip = True
    else:
        all_bulletins_as_list = []
        all_products_as_list = []
        for file_name in sorted(os.listdir(ntap_bulletins_folder)):
            if file_name.startswith("NTAP") and file_name.endswith(".json"):
                file_path = os.path.join(ntap_bulletins_folder, file_name)
                with open(file_path, 'r', encoding="utf-8") as file_in:
                    kb_data = json.loads(file_in.read())
                    all_bulletins_as_list.append(kb_data)
                    kbu_list = kb_data["kb_unaffected_list"]
                    kba_list = kb_data["kb_affected_list"]
                    kbi_list = kb_data["kb_investigating_list"]
                    for product in kbu_list:
                        if product == "Clustered Data ONTAP":
                            product = "ONTAP 9 (formerly Clustered Data ONTAP)"
                        all_products_as_list.append(product)
                    for product in kba_list:
                        if product == "Clustered Data ONTAP":
                            product = "ONTAP 9 (formerly Clustered Data ONTAP)"
                        all_products_as_list.append(product)
                    for product in kbi_list:
                        if product == "Clustered Data ONTAP":
                            product = "ONTAP 9 (formerly Clustered Data ONTAP)"
                        all_products_as_list.append(product)
        all_products_as_list = sorted(list(set(all_products_as_list)))
        json_string = json.dumps(all_products_as_list, indent=4, sort_keys=False)
        with open(all_products_json, "w", encoding="utf-8") as json_out:
            json_out.write(json_string)

        json_string = json.dumps(all_bulletins_as_list, indent=4, sort_keys=False)
        json_string = json_string.replace('"Clustered Data ONTAP"', '"ONTAP 9 (formerly Clustered Data ONTAP)"')
        with open(all_bulletins_json, "w", encoding="utf-8") as json_out:
            json_out.write(json_string)
    print("exited:".ljust(30), "create_bulletins_products")


def create_baseline_reports(application_list, today):
    print("entered:".ljust(30), "create_baseline_reports")
    script_path = os.path.dirname(os.path.realpath(__file__))
    data_folder = os.path.join(script_path, 'data')
    ntap_bulletins_folder = os.path.join(data_folder, 'bulletins', today)
    all_bulletins_json = os.path.join(ntap_bulletins_folder, "ALL_BULLETINS.json")
    all_products_json = os.path.join(ntap_bulletins_folder, "ALL_PRODUCTS.json")

    """ Try to figure out CVEs Per Application. """
    with open(all_bulletins_json, 'r', encoding="utf-8") as file_in:
        all_bulletins_as_list = json.loads(file_in.read())

    for app in application_list:
        application_key = app["app_key"]
        application_name = app["application_name"]
        application_versions = app["app_versions"]
        key = [{
            "application_key": application_key,
            "application_name": application_name,
            "application_versions": application_versions
           }]
        app_details_json = os.path.join(ntap_bulletins_folder, "APP_" + application_key + "_details.json")
        json_string = json.dumps(key, indent=4, sort_keys=False)
        with open(app_details_json, "w", encoding="utf-8") as json_out:
            json_out.write(json_string)

        app_open_json = os.path.join(ntap_bulletins_folder, "APP_" + application_key + "_open.json")
        app_closed_json = os.path.join(ntap_bulletins_folder, "APP_" + application_key + "_closed.json")

        """ Read through and find all affected, investigating. """
        kb_open_list = []
        kb_closed_list = []
        for kb_data in all_bulletins_as_list:
            ntap_advisory_id = kb_data["ntap_advisory_id"]
            kba_list = kb_data["kb_affected_list"]
            kbi_list = kb_data["kb_investigating_list"]
            kbu_list = kb_data["kb_unaffected_list"]
            for product in kba_list:
                if product.lower() == application_name.lower():
                    kb_open_list.append(ntap_advisory_id)
            for product in kbi_list:
                if product.lower() == application_name.lower():
                    kb_open_list.append(ntap_advisory_id)
            for product in kbu_list:
                if product.lower() == application_name.lower():
                    kb_closed_list.append(ntap_advisory_id)

        kb_open_list = sorted(list(set(kb_open_list)))
        json_string = json.dumps(kb_open_list, indent=4, sort_keys=True)
        with open(app_open_json, "w", encoding="utf-8") as json_out:
            json_out.write(json_string)

        kb_closed_list = sorted(list(set(kb_closed_list)))
        json_string = json.dumps(kb_closed_list, indent=4, sort_keys=True)
        with open(app_closed_json, "w", encoding="utf-8") as json_out:
            json_out.write(json_string)

    print("exited:".ljust(30), "create_baseline_reports")


def find_open_advisories_by_version(application_list, today):
    print("entered:".ljust(30), "find_open_advisories_by_version")

    current_time_stamp = datetime.now()
    date_stamp = current_time_stamp.strftime("%Y%m%d")

    script_path = os.path.dirname(os.path.realpath(__file__))
    data_folder = os.path.join(script_path, 'data')
    ntap_bulletins_folder = os.path.join(data_folder, 'bulletins', today)

    all_bulletins_json = os.path.join(ntap_bulletins_folder, "ALL_BULLETINS.json")
    with open(all_bulletins_json, 'r', encoding="utf-8") as file_in:
        all_bulletins_as_list = json.loads(file_in.read())

    for app in application_list:
        application_key = app["app_key"]
        application_name = app["application_name"]
        application_versions = app["app_versions"]

        if application_key == "ONTAP":
            application_versions.extend(application_versions)

        app_versions_lookup = os.path.join(data_folder, application_key + "_versions.json")

        print("application_name:".ljust(30), application_name)
        print("application_key:".ljust(30), application_key)
        print("application_versions:".ljust(30), application_versions)
        print("app_versions_lookup:".ljust(30), app_versions_lookup)
        with open(app_versions_lookup, 'r', encoding="utf-8") as app_version_in:
            vendor_releases = json.loads(app_version_in.read())

        app_details_json = os.path.join(ntap_bulletins_folder, "APP_" + application_key + "_details.json")
        app_open_json = os.path.join(ntap_bulletins_folder, "APP_" + application_key + "_open.json")
        app_closed_json = os.path.join(ntap_bulletins_folder, "APP_" + application_key + "_closed.json")
        formatted_open_json = os.path.join(ntap_bulletins_folder, "APP_" + application_key + "_CHECK_OPEN.json")
        formatted_close_json = os.path.join(ntap_bulletins_folder, "APP_" + application_key + "_CHECK_CLOSE.json")
        formatted_open = []
        formatted_closed = []
        with open(app_open_json, 'r', encoding="utf-8") as file_in:
            kb_open_list = json.loads(file_in.read())
        for kb_number in kb_open_list:
            for kb_data in all_bulletins_as_list:
                ntap_advisory_id = kb_data["ntap_advisory_id"]
                if kb_number == ntap_advisory_id:
                    kb_cve = kb_data["kb_cve"]
                    kb_scoring_calc = kb_data["kb_scoring_calc"]
                    kb_impact = cleanhtml(kb_data["kb_impact"].replace("\n", "").replace("\r", ""))

                    kb_title = cleanhtml(kb_data["kb_title"].replace("\n", "").replace("\r", ""))
                    kb_summary = cleanhtml(kb_data["kb_summary"].replace("\n", "").replace("\r", ""))

                    kb_rev_history = kb_data["kb_rev_history"]
                    kb_status = kb_data["kb_status"].replace("\n", "").replace("\r", "")
                    kb_workarounds = cleanhtml(str(kb_data["kb_workarounds"]).replace("\n", "").replace("\r", ""))
                    kb_fixes = kb_data["kb_fixes"]
                    kb_release_date = 19750101
                    kb_release_version = "1.0"
                    kb_last_update = 19750101
                    kb_last_version = "1.0"
                    for rev_info in kb_rev_history:
                        edit_date = int(rev_info["date"])
                        rev_ver = rev_info["version"]
                        if kb_release_date == 19750101:
                            kb_release_date = int(edit_date)
                        if edit_date > kb_last_update:
                            kb_last_update = int(edit_date)
                            kb_last_version = rev_ver

                    if len(str(kb_release_date)) > 8:
                        kb_release_date = str(kb_release_date)[:-1]
                        kb_release_date = int(kb_release_date)
                    if len(str(kb_last_update)) > 8:
                        kb_last_update = str(kb_last_update)[:-1]
                        kb_last_update = int(kb_last_update)

                    # print("ntap_advisory_id:".ljust(30), ntap_advisory_id)
                    # print("date_stamp:".ljust(30), date_stamp)
                    # print("kb_release_date:".ljust(30), kb_release_date)
                    # print("kb_last_update:".ljust(30), kb_last_update)
                    kb_days_open = days_active(date_stamp, int(kb_release_date))
                    kb_days_since_update = days_active(date_stamp, int(kb_last_update))

                    cve_5_critical_list = []
                    cve_4_highs_list = []
                    cve_3_mediums_list = []
                    cve_2_lows_list = []
                    cve_1_infos_list = []
                    kb_highest_int = 0
                    kb_highest = ""

                    for kb_cve_number in kb_cve:
                        kb_calc_score = 0
                        kb_calc_range = ""
                        kb_cve_number = kb_cve_number.split(":")[0]
                        # print("kb_cve_number:".ljust(30), kb_cve_number)
                        try:
                            kb_calc_score = kb_scoring_calc[kb_cve_number]["score"]
                            kb_calc_range = kb_scoring_calc[kb_cve_number]["range"]
                            # print("kb_calc_score:".ljust(30), kb_calc_score)
                            # print("kb_calc_range:".ljust(30), kb_calc_range)
                        except KeyError:
                            try:
                                kb_calc_score = kb_scoring_calc[""]["score"]
                                kb_calc_range = kb_scoring_calc[""]["range"]
                                # print("kb_calc_score:".ljust(30), kb_calc_score)
                                # print("kb_calc_range:".ljust(30), kb_calc_range)
                            except KeyError:
                                for key, value in kb_scoring_calc.items():
                                    if key.strip() == kb_cve_number:
                                        kb_calc_score = value["score"]
                                        kb_calc_range = value["range"]
                                        # print("kb_calc_score:".ljust(30), kb_calc_score)
                                        # print("kb_calc_range:".ljust(30), kb_calc_range)

                        if float(kb_calc_score) >= kb_highest_int:
                            kb_highest = kb_cve_number + " " + kb_calc_range + " " + str(kb_calc_score)

                    fixed_versions = []
                    if len(kb_fixes) > 0:
                        for fix_key in kb_fixes:
                            fixed_product = fix_key["product"]
                            if fixed_product.lower() == application_name.lower():
                                try:
                                    fix_list = fix_key["fixes"]
                                    for key_name in fix_list:
                                        fix_link = key_name["link"]
                                        if "index" in fix_link:
                                            fix_link = fix_link.replace("/index.html", "")
                                        if "downloads" in fix_link:
                                            fix_link = fix_link.replace("/downloads", "")
                                        fix_link = fix_link.rstrip("/")
                                        version_number = fix_link.split("/")[-1]
                                        fixed_versions.append(version_number)
                                except KeyError:
                                    fixed_versions.append("none")

                    if kb_workarounds == "None at this time.":
                        kb_workarounds = []

                    keep_kb_number = True
                    for my_app_installed_version in application_versions:
                        my_app_release = ""
                        for k_app, k_ver in vendor_releases.items():
                            if k_app == my_app_installed_version:
                                my_app_release = k_ver
                                break

                        # print("my_app_installed_version:".ljust(30), my_app_installed_version, my_app_release)
                        for fixed_version in fixed_versions:
                            for k_app, k_ver in vendor_releases.items():
                                if k_app == fixed_version:
                                    fixed_release = k_ver
                                    if my_app_release >= fixed_release:
                                        # print("IS ALREADY AT A FIXED VERSION")
                                        # print("fixed_version:".ljust(30), fixed_version, fixed_release)
                                        keep_kb_number = False
                                        break

                    my_key = {
                        "KB_KEEP": keep_kb_number,
                        "kb_number": kb_number,
                        "kb_status": kb_status,
                        "kb_release_date": kb_release_date,
                        "kb_highest": kb_highest,
                        "fixed_versions": fixed_versions,
                        "kb_title": kb_title,
                        "kb_summary": kb_summary,
                        "kb_impact": kb_impact,
                        "kb_days_open": kb_days_open,
                        "kb_last_update": kb_last_update,
                        "kb_days_since_update": kb_days_since_update,
                        "kb_total_cve": len(kb_cve),
                        "cve_5_critical": len(cve_5_critical_list),
                        "cve_5_criticals": cve_5_critical_list,
                        "cve_4_high": len(cve_4_highs_list),
                        "cve_4_highs": cve_4_highs_list,
                        "cve_3_medium": len(cve_3_mediums_list),
                        "cve_3_mediums": cve_3_mediums_list,
                        "cve_2_low": len(cve_2_lows_list),
                        "cve_2_lows": cve_2_lows_list,
                        "cve_1_info": len(cve_1_infos_list),
                        "cve_1_infos": cve_1_infos_list,
                        "kb_cve": kb_cve,
                        "kb_workarounds": kb_workarounds
                    }
                    if keep_kb_number:
                        formatted_open.append(my_key)
                    else:
                        formatted_closed.append(my_key)

            json_string = json.dumps(formatted_open, indent=4, sort_keys=False)
            with open(formatted_open_json, "w", encoding="utf-8") as json_out:
                json_out.write(json_string)

            json_string = json.dumps(formatted_closed, indent=4, sort_keys=False)
            with open(formatted_close_json, "w", encoding="utf-8") as json_out:
                json_out.write(json_string)

            csv_out = formatted_open_json.replace(".json", ".csv")
            with open(formatted_open_json, encoding='utf-8') as input_file:
                df = pd.read_json(input_file)
            df.to_csv(csv_out, encoding='utf-8', index=False)

            csv_out = formatted_close_json.replace(".json", ".csv")
            with open(formatted_close_json, encoding='utf-8') as input_file:
                df = pd.read_json(input_file)
            df.to_csv(csv_out, encoding='utf-8', index=False)


    print("exited:".ljust(30), "find_open_advisories_by_version")


def cleanup_old_dates():
    cleanup_count = 0
    print("entered:".ljust(30), "cleanup_old_dates")
    script_path = os.path.dirname(os.path.realpath(__file__))
    data_folder = os.path.join(script_path, 'data')
    ntap_bulletins_folder = os.path.join(data_folder, 'bulletins')
    for dated_folder in sorted(os.listdir(ntap_bulletins_folder)):
        ntap_bulletins_dated_folder = os.path.join(ntap_bulletins_folder, dated_folder)
        for file_name in sorted(os.listdir(ntap_bulletins_dated_folder)):
            all_bulletins_json = os.path.join(ntap_bulletins_dated_folder, "ALL_BULLETINS.json")
            if os.path.exists(all_bulletins_json):
                ntap_urls = os.path.join(ntap_bulletins_dated_folder, "ntap_urls.json")
                if os.path.exists(ntap_urls):
                    cleanup_count += 1
                    os.remove(ntap_urls)
                ntap_rss = os.path.join(ntap_bulletins_dated_folder, "ntap_rss.xml")
                if os.path.exists(ntap_rss):
                    cleanup_count += 1
                    os.remove(ntap_rss)
                if file_name.startswith("NTAP") and file_name.endswith(".json"):
                    ntap_path = os.path.join(ntap_bulletins_dated_folder, file_name)
                    timestamp_of_file_modified = os.path.getmtime(ntap_path)
                    modification_date = datetime.fromtimestamp(timestamp_of_file_modified)
                    number_of_days = (datetime.now() - modification_date).days
                    if number_of_days > 2:
                        cleanup_count += 1
                        os.remove(ntap_path)
    print("removed:".ljust(30), cleanup_count)
    print("exited:".ljust(30), "cleanup_old_dates")
