import os
import time
import json
import datetime
import pandas as pd
from datetime import datetime


def version_as_number(v_string):

    dots = 0
    patches = False
    for letter in v_string:
        if letter == ".":
            dots += 1
        if letter == "P":
            patches = True

    if patches:
        major_minor = v_string.split("P")[0].rstrip(".")
        patch_number = v_string.split("P")[1]
        patch_number = str(patch_number).zfill(2)
    else:
        major_minor = v_string.rstrip(".")
        patch_number = str(00)

    try:
        major = major_minor.split(".")[0]
    except IndexError:
        major = str(00)

    try:
        minor = major_minor.split(".")[1]
        minor = str(minor).zfill(2)
    except IndexError:
        minor = str(00)
    try:
        special = major_minor.split(".")[2]
        special = str(special).zfill(2)
    except IndexError:
        special = str(00)

    iv_number = major + minor + special + "." + patch_number
    iv_number = float(iv_number)
    # print()
    # print("version:", v_string)
    # print("major:", major)
    # print("minor:", minor)
    # print("special:", special)
    # print("patch_number:", patch_number)
    # print("iv_number:", iv_number)

    return iv_number


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


def create_bulletins_products():
    print("entered:".ljust(30), "create_bulletins_products")
    script_path = os.path.dirname(os.path.realpath(__file__))
    data_folder = os.path.join(script_path, 'data')
    ntap_bulletins_folder = os.path.join(data_folder, 'bulletins')
    for dated_folder in sorted(os.listdir(ntap_bulletins_folder)):
        ntap_bulletins_dated_folder = os.path.join(ntap_bulletins_folder, dated_folder)
        all_bulletins_json = os.path.join(ntap_bulletins_dated_folder, "ALL_BULLETINS.json")
        all_products_json = os.path.join(ntap_bulletins_dated_folder, "ALL_PRODUCTS.json")
        if os.path.exists(all_bulletins_json) and os.path.exists(all_products_json):
            skip = True
        else:
            print("Create:".ljust(30), all_bulletins_json)
            print("Create:".ljust(30), all_products_json)
            all_bulletins_as_list = []
            all_products_as_list = []
            for file_name in sorted(os.listdir(ntap_bulletins_dated_folder)):
                if file_name.startswith("NTAP") and file_name.endswith(".json"):
                    file_path = os.path.join(ntap_bulletins_dated_folder, file_name)
                    with open(file_path, 'r', encoding="utf-8") as file_in:
                        kb_data = json.loads(file_in.read())
                        all_bulletins_as_list.append(kb_data)
                        kbu_list = kb_data["kb_unaffected_list"]
                        kba_list = kb_data["kb_affected_list"]
                        kbi_list = kb_data["kb_investigating_list"]
                        for product in kbu_list:
                            all_products_as_list.append(product)
                        for product in kba_list:
                            all_products_as_list.append(product)
                        for product in kbi_list:
                            all_products_as_list.append(product)
            all_products_as_list = sorted(list(set(all_products_as_list)))
            json_string = json.dumps(all_products_as_list, indent=4, sort_keys=False)
            with open(all_products_json, "w", encoding="utf-8") as json_out:
                json_out.write(json_string)

            json_string = json.dumps(all_bulletins_as_list, indent=4, sort_keys=False)
            with open(all_bulletins_json, "w", encoding="utf-8") as json_out:
                json_out.write(json_string)
    print("exited:".ljust(30), "create_bulletins_products")


def create_baseline_reports(application_list):
    print("entered:".ljust(30), "create_baseline_reports")
    script_path = os.path.dirname(os.path.realpath(__file__))
    data_folder = os.path.join(script_path, 'data')
    ntap_bulletins_folder = os.path.join(data_folder, 'bulletins')
    for dated_folder in sorted(os.listdir(ntap_bulletins_folder)):
        ntap_bulletins_dated_folder = os.path.join(ntap_bulletins_folder, dated_folder)
        all_bulletins_json = os.path.join(ntap_bulletins_dated_folder, "ALL_BULLETINS.json")
        all_products_json = os.path.join(ntap_bulletins_dated_folder, "ALL_PRODUCTS.json")

        """ Try to figure out CVEs Per Application. """
        with open(all_bulletins_json, 'r', encoding="utf-8") as file_in:
            all_bulletins_as_list = json.loads(file_in.read())

        app_keys = []
        for app in application_list:
            application_key = app["app_key"]
            app_keys.append(application_key)
        app_keys = list(set(app_keys))

        app_versions_installed = []
        for ak in app_keys:
            for app in application_list:
                application_key = app["app_key"]
                if ak == application_key:
                    application_versions = app["app_versions"]
                    for v_number in application_versions:
                        formatted_version = version_as_number(v_number)
                        app_versions_installed.append(formatted_version)

        for app in application_list:
            application_key = app["app_key"]
            application_name = app["application_name"]
            application_versions = app["app_versions"]
            key = [{
                "application_key": application_key,
                "application_name": application_name,
                "application_versions": application_versions
               }]
            app_details_json = os.path.join(ntap_bulletins_dated_folder, "APP_" + application_key + "_details.json")
            json_string = json.dumps(key, indent=4, sort_keys=False)
            with open(app_details_json, "w", encoding="utf-8") as json_out:
                json_out.write(json_string)

            app_open_json = os.path.join(ntap_bulletins_dated_folder, "APP_" + application_key + "_open.json")
            app_closed_json = os.path.join(ntap_bulletins_dated_folder, "APP_" + application_key + "_closed.json")

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
            json_string = json.dumps(kb_open_list, indent=4, sort_keys=False)
            with open(app_open_json, "w", encoding="utf-8") as json_out:
                json_out.write(json_string)

            kb_closed_list = sorted(list(set(kb_closed_list)))
            json_string = json.dumps(kb_closed_list, indent=4, sort_keys=False)
            with open(app_closed_json, "w", encoding="utf-8") as json_out:
                json_out.write(json_string)

            # print()
            # print()
            # print("Date Being Checked:".ljust(30), dated_folder)
            # print("all_bulletins_as_list:".ljust(30), len(all_bulletins_as_list))
            # print("application_key:".ljust(30), application_key)
            # print("application_name:".ljust(30), application_name)
            # print("application_versions:".ljust(30), application_versions)
            # print("kb_open_list:".ljust(30), len(kb_open_list))
            # print("kb_closed_list:".ljust(30), len(kb_closed_list))
            # print()
    print("exited:".ljust(30), "create_baseline_reports")


def find_open_advisories_by_version(application_list):
    print("entered:".ljust(30), "find_open_advisories_by_version")
    script_path = os.path.dirname(os.path.realpath(__file__))
    data_folder = os.path.join(script_path, 'data')
    ntap_bulletins_folder = os.path.join(data_folder, 'bulletins')
    for dated_folder in sorted(os.listdir(ntap_bulletins_folder)):
        ntap_bulletins_dated_folder = os.path.join(ntap_bulletins_folder, dated_folder)
        all_bulletins_json = os.path.join(ntap_bulletins_dated_folder, "ALL_BULLETINS.json")
        with open(all_bulletins_json, 'r', encoding="utf-8") as file_in:
            all_bulletins_as_list = json.loads(file_in.read())

        for app in application_list:
            application_key = app["app_key"]
            application_name = app["application_name"]
            # if "ONTAP" not in application_name:
            #     continue

            application_versions = app["app_versions"]
            app_details_json = os.path.join(ntap_bulletins_dated_folder, "APP_" + application_key + "_details.json")
            app_open_json = os.path.join(ntap_bulletins_dated_folder, "APP_" + application_key + "_open.json")
            app_closed_json = os.path.join(ntap_bulletins_dated_folder, "APP_" + application_key + "_closed.json")
            formatted_open_json = os.path.join(ntap_bulletins_dated_folder, "APP_" + application_key + "_formatted.json")
            versions_as_numbers = []
            formatted_list = []
            with open(app_details_json, 'r', encoding="utf-8") as file_in:
                app_details_list = json.loads(file_in.read())
                for ver_number in app_details_list:
                    vnums = ver_number["application_versions"]
                    for vnum in vnums:
                        fnum = version_as_number(vnum)
                        versions_as_numbers.append(fnum)

            with open(app_open_json, 'r', encoding="utf-8") as file_in:
                kb_open_list = json.loads(file_in.read())
            with open(app_closed_json, 'r', encoding="utf-8") as file_in:
                kb_closed_list = json.loads(file_in.read())

            for kb_number in kb_open_list:
                for kb_data in all_bulletins_as_list:
                    ntap_advisory_id = kb_data["ntap_advisory_id"]
                    if kb_number == ntap_advisory_id:
                        kb_cve = kb_data["kb_cve"]
                        kb_scoring_calc = kb_data["kb_scoring_calc"]
                        kb_impact = kb_data["kb_impact"].replace("\n", "").replace("\r", "")
                        kb_title = kb_data["kb_title"].replace("\n", "").replace("\r", "")
                        kb_summary = kb_data["kb_summary"].replace("\n", "").replace("\r", "")
                        kb_rev_history = kb_data["kb_rev_history"]
                        kb_status = kb_data["kb_status"].replace("\n", "").replace("\r", "")
                        kb_workarounds = str(kb_data["kb_workarounds"]).replace("\n", "").replace("\r", "")
                        kb_fixes = kb_data["kb_fixes"]

                        kb_release_date = 00000000
                        kb_release_version = ""
                        kb_last_update = 00000000
                        kb_last_version = ""
                        for rev_info in kb_rev_history:
                            edit_date = int(rev_info["date"])
                            rev_ver = rev_info["version"]
                            if kb_release_date == 0:
                                kb_release_date = edit_date
                                kb_release_version = rev_ver
                            if edit_date > kb_last_update:
                                kb_last_update = edit_date
                                kb_last_version = rev_ver

                        current_time_stamp = datetime.now()
                        date_stamp = current_time_stamp.strftime("%Y%m%d")
                        if kb_release_date == 0:
                            kb_release_date = ntap_advisory_id.split("-")[1]
                            kb_days_open = days_active(date_stamp, int(kb_release_date))
                        else:
                            kb_days_open = days_active(date_stamp, int(kb_release_date))

                        if kb_last_update == 0:
                            kb_last_update = ntap_advisory_id.split("-")[1]
                            kb_days_since_update = days_active(date_stamp, int(kb_last_update))
                        else:
                            kb_days_since_update = days_active(date_stamp, int(kb_last_update))

                        cve_5_critical_list = []
                        cve_4_highs_list = []
                        cve_3_mediums_list = []
                        cve_2_lows_list = []
                        cve_1_infos_list = []
                        kb_highest_int = 0
                        kb_highest = ""
                        for kb_cve_number in kb_cve:
                            kb_calc_score = float(kb_scoring_calc[kb_cve_number]["score"])
                            kb_calc_range = kb_scoring_calc[kb_cve_number]["range"]

                            if kb_calc_range == "CRITICAL":
                                cve_5_critical_list.append(kb_cve_number)
                            elif kb_calc_range == "HIGH":
                                cve_4_highs_list.append(kb_cve_number)
                            elif kb_calc_range == "MEDIUM":
                                cve_3_mediums_list.append(kb_cve_number)
                            elif kb_calc_range == "LOW":
                                cve_2_lows_list.append(kb_cve_number)
                            elif kb_calc_range == "LOW":
                                cve_1_infos_list.append(kb_cve_number)
                            else:
                                cve_1_infos_list.append(kb_cve_number)

                            if kb_calc_score >= kb_highest_int:
                                kb_highest = kb_cve_number + " " + kb_calc_range + " " + str(kb_calc_score)

                        fixed_versions = []
                        if len(kb_fixes) > 0:
                            for fix_key in kb_fixes:
                                fixed_product = fix_key["product"]
                                if fixed_product.lower() == application_name.lower():
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

                        # # versions_as_numbers
                        # for fixed_version_name in fixed_versions:
                        #     fixed_numeric_version = version_as_number(fixed_version_name)
                        #     for my_installed_version in versions_as_numbers:
                        #         if my_installed_version > fixed_numeric_version:
                        #             print("Installed:".ljust(10), my_installed_version, ">", fixed_numeric_version)

                        if kb_workarounds == "None at this time.":
                            kb_workarounds = []

                        my_key = {
                            "kb_number": kb_number,
                            "kb_status": kb_status,
                            "kb_release_date": kb_release_date,
                            "kb_days_open": kb_days_open,
                            "kb_last_update": kb_last_update,
                            "kb_days_since_update": kb_days_since_update,
                            "kb_title": kb_title,
                            "kb_summary": kb_summary,
                            "kb_impact": kb_impact,
                            "kb_highest": kb_highest,
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
                            "kb_workarounds": kb_workarounds,
                            "fixed_versions": fixed_versions
                        }
                        formatted_list.append(my_key)
    #                     print("Date Being Checked:".ljust(30), dated_folder)
    #                     print("application_key:".ljust(30), application_key)
    #                     print("application_name:".ljust(30), application_name)
    #                     print("kb_status:".ljust(30), kb_status)
    #                     print("kb_number:".ljust(30), kb_number)
    #                     print("kb_release_date:".ljust(30), kb_release_date)
    #                     print("kb_days_open:".ljust(30), kb_days_open)
    #                     print("kb_last_update:".ljust(30), kb_last_update)
    #                     print("kb_days_since_update:".ljust(30), kb_days_since_update)
    #                     print("kb_title:".ljust(30), kb_title)
    #                     print("kb_summary:".ljust(30), kb_summary)
    #                     print("kb_impact:".ljust(30), kb_impact)
    #                     print("kb_highest:".ljust(30), kb_highest)
    #                     print("kb_total_cve:".ljust(30), len(kb_cve))
    #                     print("all_cves:".ljust(30), kb_cve)
    #                     print("cve_5_critical:".ljust(30), len(cve_5_critical_list))
    #                     print("cve_5_critical:".ljust(30), len(cve_5_critical_list))
    #                     print("cve_4_high:".ljust(30), len(cve_4_highs_list))
    #                     print("cve_4_highs:".ljust(30), cve_4_highs_list)
    #                     print("cve_3_medium:".ljust(30), len(cve_3_mediums_list))
    #                     print("cve_3_mediums:".ljust(30), cve_3_mediums_list)
    #                     print("cve_2_low:".ljust(30), len(cve_2_lows_list))
    #                     print("cve_2_lows:".ljust(30), cve_2_lows_list)
    #                     print("cve_1_info:".ljust(30), len(cve_1_infos_list))
    #                     print("cve_1_infos:".ljust(30), cve_1_infos_list)
    #
    #                     print("kb_workarounds:".ljust(30), kb_workarounds)
    #                     print("fixed_versions:".ljust(30), fixed_versions)
    #                     print()
    #                     print()
    #                     print()
    #
    #                     # print("kb_scoring_calc:".ljust(30), kb_scoring_calc)
    #                     # print("kb_release_version:".ljust(30), kb_release_version)
    #                     # print("kb_last_version:".ljust(30), kb_last_version)
    #                     # print("kb_rev_history:".ljust(30), kb_rev_history)
    #                     # if kb_number == "NTAP-20230908-0008":
    #                     #     exit(911)
    #
            json_string = json.dumps(formatted_list, indent=4, sort_keys=False)
            with open(formatted_open_json, "w", encoding="utf-8") as json_out:
                json_out.write(json_string)

            csv_out = formatted_open_json.replace(".json", ".csv")
            with open(formatted_open_json, encoding='utf-8') as input_file:
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
            ntap_rss = os.path.join(ntap_bulletins_dated_folder, "ntap_rss.xml")
            if os.path.exists(ntap_rss):
                cleanup_count += 1
                os.remove(ntap_rss)
            if file_name.startswith("NTAP") and file_name.endswith(".json"):
                ntap_path = os.path.join(ntap_bulletins_dated_folder, file_name)
                timestamp_of_file_modified = os.path.getmtime(ntap_path)
                modification_date = datetime.fromtimestamp(timestamp_of_file_modified)
                number_of_days = (datetime.now() - modification_date).days
                if number_of_days > 12:
                    cleanup_count += 1
                    os.remove(ntap_path)
        print(dated_folder, cleanup_count)

    print("removed:".ljust(30), cleanup_count)
    print("exited:".ljust(30), "cleanup_old_dates")
