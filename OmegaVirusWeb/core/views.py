from django.shortcuts import render
from django.views.generic import TemplateView
from django.http import HttpResponse, JsonResponse
from .models import File


class MainView(TemplateView):
    template_name = 'scans.html'


def file_upload_view(request):
    # print(request.FILES)
    if request.method == 'POST':
        my_file = request.FILES.get('file')
        File.objects.create(upload=my_file)
        return HttpResponse('')
    return JsonResponse({'post': 'false'})
