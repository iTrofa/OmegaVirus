# -*- encoding: utf-8 -*-
"""
License: MIT
Copyright (c) 2019 - present AppSeed.us
"""

from django.contrib import admin
from django.urls import path, include  # add this
from core.views import MainView, file_upload_view, detail, latest  # file_detail_view
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
                  path('admin/', admin.site.urls),
                  path("", latest, name="latest"),
                  path("", include("authentication.urls")),
                  path("", include("app.urls")),
                  path('<int:file_id>', detail, name="detail"),
                  path("uploads/", file_upload_view, name="upload-view"),
              ] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
