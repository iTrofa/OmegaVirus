import math

from django.shortcuts import render, redirect
from django.views.generic import TemplateView
from django.http import HttpResponse, JsonResponse
from django.core.files.storage import FileSystemStorage
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
                # time_check += 8
                print("Scanning... " + str(time_check) + " seconds elapsed..")

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
            "positives": positives
        }

        if positives == 0:
            safety = "No security vendors flagged this file as malicious"
            context2 = {
                "safety": safety
            }
            context.update(context2)
        else:
            safety = str(positives) + " security vendors flagged this file as malicious"
            context2 = {
                "safetyPos": safety
            }
            context.update(context2)
        return render(request, "index.html", context)
    except ObjectDoesNotExist:
        return render(request, "index.html")


def detail(request, file_id):
    # return HttpResponse("<h2> Details for File id :" + str(file_id) + "</h2>")
    obj = File.objects.get(id=file_id)
    context = {
        "name": obj.name,
        "id": obj.id,
        "SHA256": obj.SHA256,
        "filepath": obj.filepath,
        "size": obj.size,
        "date": obj.date
    }
    return render(request, "index.html", context)


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

        b = File(SHA256="{0}".format(sha256.hexdigest()), name=my_file.name, filepath=path,
                 size=convert_size(my_file.size), date=now)
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

# select_date_sql  = SELECT * FROM `FileScanner_file` ORDER BY `FileScanner_file`.`date` DESC LIMIT 1
