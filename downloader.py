import os
from multiprocessing.pool import ThreadPool
import datetime
import time
import json
import bs4
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def download_cve_details():
    print("entered:".ljust(30), "download_cve_details")

    number_of_bulletins, bulletin_files, bulletin_links = html_list_cve_bulletins()

    inputs = zip(bulletin_files, bulletin_links)
    downloaded_bulletins = download_parallel(inputs)
    print("downloaded_bulletins:".ljust(30), downloaded_bulletins)

    print("exited:".ljust(30), "download_cve_details")


def download_url(args):
    t0 = time.time()
    ontap_url, file_name = args[0], args[1]
    if not os.path.exists(file_name):
        try:
            r = requests.get(ontap_url, verify=False)
            with open(file_name, 'wb') as f:
                f.write(r.content)
            return 200, ontap_url, time.time() - t0
        except Exception as e:
            print("Error with download_url():", ontap_url, e)
            return 404, ontap_url, time.time() - t0
    else:
        return 200, ontap_url, time.time() - t0


def download_parallel(args):
    print("entered:".ljust(30), "download_parallel")
    total_threads = 4
    results = ThreadPool(total_threads - 1).imap_unordered(download_url, args)
    z = 0
    for result in results:
        z += 1
        err_code = result[0]
        url_tried = result[1]
        elapsed_time = result[2]

        if err_code != 200:
            print(str(z).ljust(10), "code:", err_code, "url:", url_tried, 'time (s):', elapsed_time)
            time.sleep(3)
    print("exited:".ljust(30), "download_parallel")
    return z


def html_list_cve_bulletins():
    print("entered:".ljust(30), "html_list_cve_bulletins")
    current_time_stamp = datetime.datetime.now()
    date_stamp = current_time_stamp.strftime("%Y%m%d")

    script_path = os.path.dirname(os.path.realpath(__file__))
    data_folder = os.path.join(script_path, 'data')
    ntap_folder = os.path.join(data_folder, 'bulletins', date_stamp)
    ntap_urls = os.path.join(data_folder, 'bulletins', date_stamp, "ntap_urls.json")

    os.makedirs(data_folder, exist_ok=True)
    os.makedirs(ntap_folder, exist_ok=True)

    data_feed = "https://security.netapp.com/data/advisory/"
    html_page = requests.get(data_feed, verify=False).content
    soup_page = bs4.BeautifulSoup(html_page, features="html.parser")
    files = soup_page.find_all("a")

    json_links = []
    local_links = []
    links = 0
    for link in files:
        if len(link.attrs["href"]) > 5:
            url_link = data_feed + link.attrs["href"]
            url_save = os.path.join(ntap_folder, link.attrs["href"])
            json_links.append(url_link)
            local_links.append(url_save)
            links += 1
    json_string = json.dumps(json_links, indent=4, sort_keys=False)
    with open(ntap_urls, "w", encoding="utf-8") as json_out:
        json_out.write(json_string)
    print("exited:".ljust(30), "html_list_cve_bulletins")
    return links, json_links, local_links
