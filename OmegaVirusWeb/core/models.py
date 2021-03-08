from django.db import models


class File(models.Model):
    upload = models.FileField(upload_to='uploads/')

    class Meta:
        app_label = 'FileScanner'


def __str__(self):
    return str(self.pk)
