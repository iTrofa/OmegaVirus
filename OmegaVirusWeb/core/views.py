import math

from django.shortcuts import render, redirect
from django.views.generic import TemplateView, ListView
from django.http import HttpResponse, JsonResponse
from django.core.files.storage import FileSystemStorage
from django.utils.safestring import mark_safe
from .forms import FileForm
from .models import File, Hash
from django.utils import timezone
# import uuid
import hashlib
from django.core.exceptions import ObjectDoesNotExist
import ssdeep
import tlsh
import json
import sys
import time
import os
import subprocess
import re
from virus_total_apis import PublicApi as VirusTotalPublicApi


class MainView(TemplateView):
    template_name = 'scans.html'


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


def history(request):
    obj = File.objects.all().filter(first=True)
    historyHTML = ""
    for files in obj:
        historyHTML += '<tr><th scope="row"><div class="media align-items-center"> <div class="media-body"><span class="mb-0 text-sm">' + files.name + '</span></div></div></th><td> <a href="http://127.0.0.1:8000/' + files.SHA256 + '">' + files.SHA256 + '</a> </td>' \
                                                                                                                                                                                                                                                             '<td><span class="badge badge-dot mr-4"><i class="bg-success"></i> completed</span></td><td><div class="d-flex align-items-center"><span class="mr-2">' + files.detection + '%</span><div><div class="progress"><div class="progress-bar bg-warning" ' \
                                                                                                                                                                                                                                                                                                                                                                                                                                         'role="progressbar" aria-valuenow="' + files.detection + '" aria-valuemin="0" aria-valuemax="100" style="width: ' + files.detection + '%;"></div></div></div></div></td></tr>'
        print(files.name + " " + files.SHA256)
    context = {
        "history": mark_safe(historyHTML)
    }
    return render(request, "history.html", context)


def detailGET(request):
    if request.POST:
        search_term = request.POST['search']
        print(search_term)
        try:
            obj = File.objects.filter(SHA256=search_term).first()
            obj2 = Hash.objects.filter(SHA256=search_term).first()

            print(obj2.MD5)
            print(obj2.SHA256)
            """ AV Detection """
            vt = VirusTotalPublicApi('38afdb6f1267ae26374823c5e80d84fc977ed7b326b152d21fedd15ca29f36dc')

            """Check if file is in VT's cache"""

            response = vt.get_file_report(obj2.MD5)
            json_dump = json.dumps(response, sort_keys=False, indent=4)
            json_list = json.loads(json_dump)
            verbose_msg = ""
            for item_key, item_values in json_list.items():
                if 'results' in item_key:
                    print("Scanning... ")
                    verbose_msg = json_list['results']['verbose_msg']
            print(verbose_msg)

            if verbose_msg != "Scan finished, information embedded":
                print("Uploading file..")
                path = "/root/Desktop/OmegaVirus/OmegaVirusWeb/core/uploads/" + obj.name
                print(path)

                vt.scan_file(path)
                verbose_msg = ""
            """Scanning file"""

            time_check = 0
            while verbose_msg != "Scan finished, information embedded":
                """if verbose_msg == "Scan finished, information embedded":
                    break"""
                response = vt.get_file_report(obj2.MD5)
                json_dump = json.dumps(response, sort_keys=False, indent=4)
                json_list = json.loads(json_dump)
                for item_key, item_values in json_list.items():
                    if 'results' in item_key:
                        verbose_msg2 = verbose_msg
                        verbose_msg = json_list['results']['verbose_msg']
                        if verbose_msg != verbose_msg2:
                            if verbose_msg != "The requested resource is not among the finished, queued or pending scans":
                                print(verbose_msg)
                # time.sleep(8)
                if time_check >= 120:
                    print("Time limit surpassed")
                    sys.exit(0)
                if verbose_msg == "Your resource is queued for analysis":
                    """time_check += 8
                    print("Scanning... " + str(time_check) + " seconds elapsed..")"""

            print("outside while")
            response_code = json_list['response_code']
            scan_id = json_list['results']['scan_id']
            sha1 = json_list['results']['sha1']
            resource = json_list['results']['resource']
            scan_date = json_list['results']['scan_date']
            permalink = json_list['results']['permalink']
            sha256 = json_list['results']['sha256']
            positives = json_list['results']['positives']
            total = json_list['results']['total']
            md5 = json_list['results']['md5']

            # Liste AV -- Resultat
            liste_AV = [i for i in json_list["results"]["scans"]]
            liste_AV_result_html = [(str(i), str(json_list["results"]["scans"][i]["detected"])) for i in liste_AV]

            html = str()
            cptdetected = 0
            cptnodetected = 0
            for i, j in liste_AV_result_html:
                if j == "True":
                    html += '<tr><th scope="row"><b>' + i + '</b></th><td style="color:red;"><b>' + "Detected" + '</b></td></tr>'
                    cptdetected += 1
                if j == "False":
                    html += '<tr><th scope="row"><b>' + i + '</b></th><td style="color:green;"><b>' + "Not detected" + '</b></td></tr>'
                    cptnodetected += 1

            ###########
            # Liste Hash --- New Version
            liste_hash = [("MD5", obj2.MD5), ("SHA1", obj2.SHA1), ("SHA256", obj2.SHA256), ("SHA512", obj2.SHA512),
                          ("SSDEEP", obj2.SSDEEP), ("TLSH", obj2.TLSH)]
            html_hash = str()
            for i, j in liste_hash:
                html_hash += '<tr><th scope="row" style="color:red;"><b>' + i + '</b></th><td style="color:blue;"><b>' + j + '</b></td></tr>'
            ##############################

            ## Yara ##
            html_yara = str()
            yara_matched = (("yararule1", "posay", "30"), ("yararule2", "posay", "80"), ("yararule2", "posay", "30"),
                            ("yararule3", "posay", "80"))
            for nom_regle, j, k in yara_matched:
                html_yara += '<tr><th scope="row" style="color:red;"><b>' + nom_regle + '</b></th></tr>'

            ################# Json #############
            with open("/root/Desktop/OmegaVirus/scripts/report.json") as json_cuckoo:
                data_cuckoo = json.load(json_cuckoo)
            cuckoo_score = float(data_cuckoo["info"]["score"])
            html_cuckoo = str()
            for i in data_cuckoo["info"]:
                dico = data_cuckoo["info"][i]
                if i != "score":
                    html_cuckoo += '<tr><th scope="row">' + str(i) + '</th><td>' + str(dico) + '</td></tr>'

            ###############################################################
            html_notation = str()
            av_notation = str(cptdetected) + "/" + str(cptdetected + cptnodetected)
            av_notation_pourcent = str(int((int(cptdetected) / int(cptdetected + cptnodetected)) * 100))

            detection = (str(int((positives * 100 / total))))
            obj.detection = str(int((positives * 100 / total)))
            File.objects.filter(name=obj.name).update(detection=detection)
            obj.refresh_from_db()

            if int(float(av_notation_pourcent)) > 80:
                progress_bar_color = "success"
            elif int(float(av_notation_pourcent)) > 40:
                progress_bar_color = "primary"
            else:
                progress_bar_color = "danger"

            cuckoo_note = str(float(cuckoo_score))
            cuckoo_note_pourcent = str(int((float(cuckoo_score) / 10) * 100))

            if int(float(cuckoo_note_pourcent)) > 80:
                progress_bar_color1 = "success"
            elif int(float(cuckoo_note_pourcent)) > 40:
                progress_bar_color1 = "primary"
            else:
                progress_bar_color1 = "danger"

            html_notation += '<tr><th scope="row">Antivirus Detection</th><td>' + av_notation + '</td><td><div class="d-flex align-items-center"><span class="mr-2">' + av_notation_pourcent + '%</span><div><div class="progress"><div class="progress-bar bg-gradient-' + progress_bar_color + '" role="progressbar" aria-valuenow="60" aria-valuemin="0" aria-valuemax="100" style="width: ' + av_notation_pourcent + '%;"></div></div></div></div></td></tr>'
            html_notation += '<tr><th scope="row">Cuckoo Detection</th><td>' + cuckoo_note + '/10</td><td><div class="d-flex align-items-center"><span class="mr-2">' + cuckoo_note_pourcent + '%</span><div><div class="progress"><div class="progress-bar bg-gradient-' + progress_bar_color1 + '" role="progressbar" aria-valuenow="60" aria-valuemin="0" aria-valuemax="100" style="width: ' + cuckoo_note_pourcent + '%;"></div></div></div></div></td></tr>'

            print(response_code)
            print(scan_id)
            print(sha1)
            print(resource)
            print(scan_date)
            print(permalink)
            print(verbose_msg)
            print(sha256)
            print(positives)
            print(total)
            print(md5)
            print("Scan time taken: " + str(time_check) + " seconds.")

            context = {
                "name": obj.name,
                "id": obj.id,
                "SHA256": obj.SHA256,
                "filepath": obj.filepath,
                "size": obj.size,
                "date": obj.date,
                "MD5": obj2.MD5,
                "SHA1": obj2.SHA1,
                "SHA512": obj2.SHA512,
                "SSDEEP": obj2.SSDEEP,
                "TLSH": obj2.TLSH,
                "total": total,
                "positives": positives,
                "html": mark_safe(html),
                "html_hash": mark_safe(html_hash),
                "html_yara": mark_safe(html_yara),
                "cuckoo_score": cuckoo_score,
                "cuckoo_info": mark_safe(html_cuckoo),
                "html_notation": mark_safe(html_notation)
            }

            if positives == 0:
                safety = "OmegaVirus flagged this file as safe"
                context2 = {
                    "safety": safety
                }
                context.update(context2)
            else:
                safety = str(positives) + " OmegaVirus flagged this file as malicious"
                context2 = {
                    "safetyPos": safety
                }
                context.update(context2)
            return render(request, "index.html", context)
        except ObjectDoesNotExist:
            return render(request, "index.html")


def latest(request):
    try:
        obj = File.objects.latest('id')
        obj2 = Hash.objects.latest('id')

        print(obj2.MD5)
        print(obj2.SHA256)
        """ AV Detection """
        vt = VirusTotalPublicApi('38afdb6f1267ae26374823c5e80d84fc977ed7b326b152d21fedd15ca29f36dc')

        """Check if file is in VT's cache"""

        response = vt.get_file_report(obj2.MD5)
        json_dump = json.dumps(response, sort_keys=False, indent=4)
        json_list = json.loads(json_dump)
        verbose_msg = ""
        for item_key, item_values in json_list.items():
            if 'results' in item_key:
                print("Scanning... ")
                verbose_msg = json_list['results']['verbose_msg']
        print(verbose_msg)

        if verbose_msg != "Scan finished, information embedded":
            print("Uploading file..")
            path = "/root/Desktop/OmegaVirus/OmegaVirusWeb/core/uploads/" + obj.name
            print(path)

            vt.scan_file(path)
            verbose_msg = ""
        """Scanning file"""

        time_check = 0
        while verbose_msg != "Scan finished, information embedded":
            """if verbose_msg == "Scan finished, information embedded":
                break"""
            response = vt.get_file_report(obj2.MD5)
            json_dump = json.dumps(response, sort_keys=False, indent=4)
            json_list = json.loads(json_dump)
            for item_key, item_values in json_list.items():
                if 'results' in item_key:
                    verbose_msg2 = verbose_msg
                    verbose_msg = json_list['results']['verbose_msg']
                    if verbose_msg != verbose_msg2:
                        if verbose_msg != "The requested resource is not among the finished, queued or pending scans":
                            print(verbose_msg)
            # time.sleep(8)
            if time_check >= 120:
                print("Time limit surpassed")
                sys.exit(0)
            if verbose_msg == "Your resource is queued for analysis":
                """ # time_check += 8
                print("Scanning... " + str(time_check) + " seconds elapsed..")"""

        print("outside while")
        response_code = json_list['response_code']
        scan_id = json_list['results']['scan_id']
        sha1 = json_list['results']['sha1']
        resource = json_list['results']['resource']
        scan_date = json_list['results']['scan_date']
        permalink = json_list['results']['permalink']
        sha256 = json_list['results']['sha256']
        positives = json_list['results']['positives']
        total = json_list['results']['total']
        md5 = json_list['results']['md5']

        # Liste AV -- Resultat
        liste_AV = [i for i in json_list["results"]["scans"]]
        liste_AV_result_html = [(str(i), str(json_list["results"]["scans"][i]["detected"])) for i in liste_AV]

        html = str()
        cptdetected = 0
        cptnodetected = 0
        for i, j in liste_AV_result_html:
            if j == "True":
                html += '<tr><th scope="row"><b>' + i + '</b></th><td style="color:red;"><b>' + "Detected" + '</b></td></tr>'
                cptdetected += 1
            if j == "False":
                html += '<tr><th scope="row"><b>' + i + '</b></th><td style="color:green;"><b>' + "Not detected" + '</b></td></tr>'
                cptnodetected += 1

        ###########
        # Liste Hash --- New Version
        liste_hash = [("MD5", obj2.MD5), ("SHA1", obj2.SHA1), ("SHA256", obj2.SHA256), ("SHA512", obj2.SHA512),
                      ("SSDEEP", obj2.SSDEEP), ("TLSH", obj2.TLSH)]
        html_hash = str()
        for i, j in liste_hash:
            html_hash += '<tr><th scope="row" style="color:red;"><b>' + i + '</b></th><td style="color:blue;"><b>' + j + '</b></td></tr>'
        ##############################

        ## Yara ##
        html_yara = str()
        yara_matched = (("yararule1", "posay", "30"), ("yararule2", "posay", "80"), ("yararule2", "posay", "30"),
                        ("yararule3", "posay", "80"))
        for nom_regle, j, k in yara_matched:
            html_yara += '<tr><th scope="row" style="color:red;"><b>' + nom_regle + '</b></th></tr>'

        ################# Json #############
        with open("/root/Desktop/OmegaVirus/scripts/report.json") as json_cuckoo:
            data_cuckoo = json.load(json_cuckoo)
        cuckoo_score = float(data_cuckoo["info"]["score"])
        html_cuckoo = str()
        for i in data_cuckoo["info"]:
            dico = data_cuckoo["info"][i]
            if i != "score":
                html_cuckoo += '<tr><th scope="row">' + str(i) + '</th><td>' + str(dico) + '</td></tr>'

        ###############################################################
        html_notation = str()
        av_notation = str(cptdetected) + "/" + str(cptdetected + cptnodetected)
        av_notation_pourcent = str(int((int(cptdetected) / int(cptdetected + cptnodetected)) * 100))

        detection = (str(int((positives * 100 / total))))
        obj.detection = str(int((positives * 100 / total)))
        File.objects.filter(name=obj.name).update(detection=detection)
        obj.refresh_from_db()

        if int(float(av_notation_pourcent)) > 80:
            progress_bar_color = "success"
        elif int(float(av_notation_pourcent)) > 40:
            progress_bar_color = "primary"
        else:
            progress_bar_color = "danger"

        cuckoo_note = str(float(cuckoo_score))
        cuckoo_note_pourcent = str(int((float(cuckoo_score) / 10) * 100))

        if int(float(cuckoo_note_pourcent)) > 80:
            progress_bar_color1 = "success"
        elif int(float(cuckoo_note_pourcent)) > 40:
            progress_bar_color1 = "primary"
        else:
            progress_bar_color1 = "danger"

        html_notation += '<tr><th scope="row">Antivirus Detection</th><td>' + av_notation + '</td><td><div class="d-flex align-items-center"><span class="mr-2">' + av_notation_pourcent + '%</span><div><div class="progress"><div class="progress-bar bg-gradient-' + progress_bar_color + '" role="progressbar" aria-valuenow="60" aria-valuemin="0" aria-valuemax="100" style="width: ' + av_notation_pourcent + '%;"></div></div></div></div></td></tr>'
        html_notation += '<tr><th scope="row">Cuckoo Detection</th><td>' + cuckoo_note + '/10</td><td><div class="d-flex align-items-center"><span class="mr-2">' + cuckoo_note_pourcent + '%</span><div><div class="progress"><div class="progress-bar bg-gradient-' + progress_bar_color1 + '" role="progressbar" aria-valuenow="60" aria-valuemin="0" aria-valuemax="100" style="width: ' + cuckoo_note_pourcent + '%;"></div></div></div></div></td></tr>'

        print(response_code)
        print(scan_id)
        print(sha1)
        print(resource)
        print(scan_date)
        print(permalink)
        print(verbose_msg)
        print(sha256)
        print(positives)
        print(total)
        print(md5)
        print("Scan time taken: " + str(time_check) + " seconds.")

        context = {
            "name": obj.name,
            "id": obj.id,
            "SHA256": obj.SHA256,
            "filepath": obj.filepath,
            "size": obj.size,
            "date": obj.date,
            "MD5": obj2.MD5,
            "SHA1": obj2.SHA1,
            "SHA512": obj2.SHA512,
            "SSDEEP": obj2.SSDEEP,
            "TLSH": obj2.TLSH,
            "total": total,
            "positives": positives,
            "html": mark_safe(html),
            "html_hash": mark_safe(html_hash),
            "html_yara": mark_safe(html_yara),
            "cuckoo_score": cuckoo_score,
            "cuckoo_info": mark_safe(html_cuckoo),
            "html_notation": mark_safe(html_notation)
        }

        if positives == 0:
            safety = "OmegaVirus flagged this file as safe"
            context2 = {
                "safety": safety
            }
            context.update(context2)
        else:
            safety = str(positives) + " OmegaVirus flagged this file as malicious"
            context2 = {
                "safetyPos": safety
            }
            context.update(context2)
        return render(request, "index.html", context)
    except ObjectDoesNotExist:
        return render(request, "index.html")


def detail(request, file_id):
    # return HttpResponse("<h2> Details for File id :" + str(file_id) + "</h2>")
    try:

        obj = File.objects.filter(SHA256=file_id).first()
        obj2 = Hash.objects.filter(SHA256=file_id).first()

        print(obj2.MD5)
        print(obj2.SHA256)
        """ AV Detection """
        vt = VirusTotalPublicApi('38afdb6f1267ae26374823c5e80d84fc977ed7b326b152d21fedd15ca29f36dc')

        """Check if file is in VT's cache"""

        response = vt.get_file_report(obj2.MD5)
        json_dump = json.dumps(response, sort_keys=False, indent=4)
        json_list = json.loads(json_dump)
        verbose_msg = ""
        for item_key, item_values in json_list.items():
            if 'results' in item_key:
                print("Scanning... ")
                verbose_msg = json_list['results']['verbose_msg']
        print(verbose_msg)

        if verbose_msg != "Scan finished, information embedded":
            print("Uploading file..")
            path = "/root/Desktop/OmegaVirus/OmegaVirusWeb/core/uploads/" + obj.name
            print(path)

            vt.scan_file(path)
            verbose_msg = ""
        """Scanning file"""

        time_check = 0
        while verbose_msg != "Scan finished, information embedded":
            """if verbose_msg == "Scan finished, information embedded":
                break"""
            response = vt.get_file_report(obj2.MD5)
            json_dump = json.dumps(response, sort_keys=False, indent=4)
            json_list = json.loads(json_dump)
            for item_key, item_values in json_list.items():
                if 'results' in item_key:
                    verbose_msg2 = verbose_msg
                    verbose_msg = json_list['results']['verbose_msg']
                    if verbose_msg != verbose_msg2:
                        if verbose_msg != "The requested resource is not among the finished, queued or pending scans":
                            print(verbose_msg)
            # time.sleep(8)
            if time_check >= 120:
                print("Time limit surpassed")
                sys.exit(0)
            if verbose_msg == "Your resource is queued for analysis":
                """     # time_check += 8
                print("Scanning... " + str(time_check) + " seconds elapsed..") """

        print("outside while")
        response_code = json_list['response_code']
        scan_id = json_list['results']['scan_id']
        sha1 = json_list['results']['sha1']
        resource = json_list['results']['resource']
        scan_date = json_list['results']['scan_date']
        permalink = json_list['results']['permalink']
        sha256 = json_list['results']['sha256']
        positives = json_list['results']['positives']
        total = json_list['results']['total']
        md5 = json_list['results']['md5']

        # Liste AV -- Resultat
        liste_AV = [i for i in json_list["results"]["scans"]]
        liste_AV_result_html = [(str(i), str(json_list["results"]["scans"][i]["detected"])) for i in liste_AV]

        html = str()
        cptdetected = 0
        cptnodetected = 0
        for i, j in liste_AV_result_html:
            if j == "True":
                html += '<tr><th scope="row"><b>' + i + '</b></th><td style="color:red;"><b>' + "Detected" + '</b></td></tr>'
                cptdetected += 1
            if j == "False":
                html += '<tr><th scope="row"><b>' + i + '</b></th><td style="color:green;"><b>' + "Not detected" + '</b></td></tr>'
                cptnodetected += 1

        ###########
        # Liste Hash --- New Version
        liste_hash = [("MD5", obj2.MD5), ("SHA1", obj2.SHA1), ("SHA256", obj2.SHA256), ("SHA512", obj2.SHA512),
                      ("SSDEEP", obj2.SSDEEP), ("TLSH", obj2.TLSH)]
        html_hash = str()
        for i, j in liste_hash:
            html_hash += '<tr><th scope="row" style="color:red;"><b>' + i + '</b></th><td style="color:blue;"><b>' + j + '</b></td></tr>'
        ##############################

        ## Yara ##
        html_yara = str()
        yara_matched = (("yararule1", "posay", "30"), ("yararule2", "posay", "80"), ("yararule2", "posay", "30"),
                        ("yararule3", "posay", "80"))
        for nom_regle, j, k in yara_matched:
            html_yara += '<tr><th scope="row" style="color:red;"><b>' + nom_regle + '</b></th></tr>'

        ################# Json #############
        with open("/root/Desktop/OmegaVirus/scripts/report.json") as json_cuckoo:
            data_cuckoo = json.load(json_cuckoo)
        cuckoo_score = float(data_cuckoo["info"]["score"])
        html_cuckoo = str()
        for i in data_cuckoo["info"]:
            dico = data_cuckoo["info"][i]
            if i != "score":
                html_cuckoo += '<tr><th scope="row">' + str(i) + '</th><td>' + str(dico) + '</td></tr>'

        ###############################################################
        html_notation = str()
        av_notation = str(cptdetected) + "/" + str(cptdetected + cptnodetected)
        av_notation_pourcent = str(int((int(cptdetected) / int(cptdetected + cptnodetected)) * 100))

        detection = (str(int((positives * 100 / total))))
        obj.detection = str(int((positives * 100 / total)))
        File.objects.filter(name=obj.name).update(detection=detection)
        obj.refresh_from_db()

        if int(float(av_notation_pourcent)) > 80:
            progress_bar_color = "success"
        elif int(float(av_notation_pourcent)) > 40:
            progress_bar_color = "primary"
        else:
            progress_bar_color = "danger"

        cuckoo_note = str(float(cuckoo_score))
        cuckoo_note_pourcent = str(int((float(cuckoo_score) / 10) * 100))

        if int(float(cuckoo_note_pourcent)) > 80:
            progress_bar_color1 = "success"
        elif int(float(cuckoo_note_pourcent)) > 40:
            progress_bar_color1 = "primary"
        else:
            progress_bar_color1 = "danger"

        html_notation += '<tr><th scope="row">Antivirus Detection</th><td>' + av_notation + '</td><td><div class="d-flex align-items-center"><span class="mr-2">' + av_notation_pourcent + '%</span><div><div class="progress"><div class="progress-bar bg-gradient-' + progress_bar_color + '" role="progressbar" aria-valuenow="60" aria-valuemin="0" aria-valuemax="100" style="width: ' + av_notation_pourcent + '%;"></div></div></div></div></td></tr>'
        html_notation += '<tr><th scope="row">Cuckoo Detection</th><td>' + cuckoo_note + '/10</td><td><div class="d-flex align-items-center"><span class="mr-2">' + cuckoo_note_pourcent + '%</span><div><div class="progress"><div class="progress-bar bg-gradient-' + progress_bar_color1 + '" role="progressbar" aria-valuenow="60" aria-valuemin="0" aria-valuemax="100" style="width: ' + cuckoo_note_pourcent + '%;"></div></div></div></div></td></tr>'

        print(response_code)
        print(scan_id)
        print(sha1)
        print(resource)
        print(scan_date)
        print(permalink)
        print(verbose_msg)
        print(sha256)
        print(positives)
        print(total)
        print(md5)
        print("Scan time taken: " + str(time_check) + " seconds.")

        context = {
            "name": obj.name,
            "id": obj.id,
            "SHA256": obj.SHA256,
            "filepath": obj.filepath,
            "size": obj.size,
            "date": obj.date,
            "MD5": obj2.MD5,
            "SHA1": obj2.SHA1,
            "SHA512": obj2.SHA512,
            "SSDEEP": obj2.SSDEEP,
            "TLSH": obj2.TLSH,
            "total": total,
            "positives": positives,
            "html": mark_safe(html),
            "html_hash": mark_safe(html_hash),
            "html_yara": mark_safe(html_yara),
            "cuckoo_score": cuckoo_score,
            "cuckoo_info": mark_safe(html_cuckoo),
            "html_notation": mark_safe(html_notation)
        }

        if positives == 0:
            safety = "OmegaVirus flagged this file as safe"
            context2 = {
                "safety": safety
            }
            context.update(context2)
        else:
            safety = str(positives) + " OmegaVirus flagged this file as malicious"
            context2 = {
                "safetyPos": safety
            }
            context.update(context2)
        return render(request, "index.html", context)
    except ObjectDoesNotExist:
        return render(request, "index.html")


def file_upload_view(request):
    print("File uploaded")
    # print(request.FILES)
    if request.method == 'POST':
        my_file = request.FILES.get('file')
        fs = FileSystemStorage()
        path = fs.save(my_file.name, my_file)
        BUF_SIZE = 65536
        now = timezone.localtime(timezone.now())
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        sha1 = hashlib.sha1()

        with open("/root/Desktop/OmegaVirus/OmegaVirusWeb/core/uploads/" + path, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha256.update(data)
                sha512.update(data)
                md5.update(data)
                sha1.update(data)
                SSDEEP = ssdeep.hash(data)
                TLSH = tlsh.hash(data)

        if File.objects.filter(SHA256=sha256.hexdigest()).exists():
            b = File(SHA256="{0}".format(sha256.hexdigest()), name=my_file.name, filepath=path, size=convert_size(my_file.size), date=now, first=False)
            b.save()

        else:
            b = File(SHA256="{0}".format(sha256.hexdigest()), name=my_file.name, filepath=path, size=convert_size(my_file.size), date=now, first=True)
            b.save()

        h = Hash(SHA256="{0}".format(sha256.hexdigest()), SHA512="{0}".format(sha512.hexdigest()),
                 SHA1="{0}".format(sha1.hexdigest()), MD5="{0}".format(md5.hexdigest()),
                 SSDEEP="{0}".format(SSDEEP), TLSH="{0}".format(TLSH))
        h.save()
    try:
        obj = File.objects.latest('id')
        print("im in")
        context = {
            "name": obj.name,
            "id": obj.id,
            "SHA256": obj.SHA256,
            "filepath": obj.filepath,
            "size": obj.size,
            "date": obj.date
        }
        return redirect('latest')
        # return render(request, "index.html", context)
    except ValueError:
        return redirect('latest')


"""
class SearchView(ListView):
    template_name = 'scans.html'
    context_object_name = 'all_search_results'


def get_queryset(self):
    result = super(SearchView, self).get_queryset()
    query = self.request.GET.get('search')
    if query:
        print(query)
    else:
        result = None
    return result"""
