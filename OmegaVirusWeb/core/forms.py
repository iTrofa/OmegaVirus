from django.forms import forms
from core.models import File


class FileForm(forms.Form):
    class Meta:
        model = File
        fields = ["uuid", "name", "filepath", "size"]
