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
            "safety": "No security vendors flagged this file as malicious"
        }
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
    print("file upload")
    # print(request.FILES)
    if request.method == 'POST':
        my_file = request.FILES.get('file')
        print(my_file.name)
        print(my_file.size)
        fs = FileSystemStorage()
        path = fs.save(my_file.name, my_file)
        BUF_SIZE = 65536
        now = timezone.localtime(timezone.now())

        with open("/root/Desktop/OmegaVirus/OmegaVirusWeb/core/uploads/" + path, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha256 = hashlib.sha256()
                sha256.update(data)
                sha512 = hashlib.sha512()
                sha512.update(data)
                md5 = hashlib.md5()
                md5.update(data)
                sha1 = hashlib.sha1()
                sha1.update(data)
                SSDEEP = ssdeep.hash(data)
                TLSH = tlsh.hash(data)

        b = File(SHA256="{0}".format(sha256.hexdigest()), name=my_file.name, filepath=path, size=convert_size(my_file.size), date=now)
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
