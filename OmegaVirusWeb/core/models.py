from django.db import models


class File(models.Model):
    SHA256 = models.CharField(max_length=250)  # , default="Error, try re-uploading file", primary_key=True)
    name = models.CharField(max_length=250)
    filepath = models.CharField(max_length=250)
    size = models.CharField(max_length=250)
    date = models.DateTimeField()

    def __str__(self):
        return self.name


class Hash(models.Model):
    SHA256 = models.CharField(max_length=250)
    SHA512 = models.CharField(max_length=250)
    SHA1 = models.CharField(max_length=250)
    MD5 = models.CharField(max_length=250)
    SSDEEP = models.CharField(max_length=250, default="")
    TLSH = models.CharField(max_length=250, default="")

    def __str__(self):
        return self.SHA256
    # class Meta:
    #    app_label = 'FileScanner'

    # return str(self.pk)

#  max_length=2,
#  default=os.path.getsize('uploads/info.py')

# size = models.CharField(
#    max_length=2,
#    default=,
# )
# name = models.CharField(max_length=500)
# filepath = models.FileField(upload_to='files/', verbose_name="")
